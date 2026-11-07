package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var errConnLost = errors.New("connection lost")

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// clientConn is one TLS connection multiplexing many streams.
type clientConn struct {
	conn   net.Conn
	wmu    sync.Mutex
	openMu sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*clientStream
	next    uint32
	err     error
	dead    chan struct{}
}

func newClientConn(conn net.Conn) *clientConn {
	cc := &clientConn{conn: conn, streams: map[uint32]*clientStream{}, dead: make(chan struct{})}
	go cc.readLoop()
	return cc
}

func (cc *clientConn) isDead() bool {
	select {
	case <-cc.dead:
		return true
	default:
		return false
	}
}

func (cc *clientConn) send(typ byte, id uint32, payload []byte) error {
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	if err := writeFrame(cc.conn, typ, id, payload); err != nil {
		cc.fail(err)
		return errConnLost
	}
	return nil
}

func (cc *clientConn) readLoop() {
	br := bufio.NewReaderSize(cc.conn, 64*1024)
	for {
		f, err := readFrame(br)
		if err != nil {
			cc.fail(err)
			return
		}
		cc.mu.Lock()
		s := cc.streams[f.stream]
		cc.mu.Unlock()
		if s == nil {
			continue
		}
		if f.typ == fCredit {
			if len(f.payload) == 4 {
				s.stdinWin.add(int64(binary.BigEndian.Uint32(f.payload)))
			}
			continue
		}
		s.in.push(f)
	}
}

func (cc *clientConn) fail(err error) {
	cc.mu.Lock()
	if cc.err != nil {
		cc.mu.Unlock()
		return
	}
	cc.err = err
	close(cc.dead)
	streams := cc.streams
	cc.streams = map[uint32]*clientStream{}
	cc.mu.Unlock()
	cc.conn.Close()
	for _, s := range streams {
		s.in.close(errConnLost)
		s.stdinWin.close()
	}
}

func (cc *clientConn) close() { cc.fail(errClosed) }

type clientStream struct {
	id       uint32
	cc       *clientConn
	in       *frameQueue
	stdinWin *window // credit for data we send (stdin, uploads)
	cr       creditor
}

func (cc *clientConn) open(req openReq) (*clientStream, error) {
	// Ids must reach the server in increasing order, so allocate and send under one lock.
	cc.openMu.Lock()
	defer cc.openMu.Unlock()
	cc.mu.Lock()
	if cc.err != nil {
		cc.mu.Unlock()
		return nil, errConnLost
	}
	cc.next++
	s := &clientStream{id: cc.next, cc: cc, in: newFrameQueue(), stdinWin: newWindow(initialWindow)}
	s.cr.grant = func(n int) { _ = cc.send(fCredit, s.id, creditPayload(n)) }
	cc.streams[s.id] = s
	cc.mu.Unlock()
	if err := cc.send(fOpen, s.id, mustJSON(req)); err != nil {
		return nil, err
	}
	return s, nil
}

// recv returns the next frame of the stream and returns flow-control credit for data frames.
func (s *clientStream) recv() (frame, error) {
	f, err := s.in.pop()
	if err != nil {
		return frame{}, err
	}
	if f.typ == fOut || f.typ == fErr {
		s.cr.consume(len(f.payload))
	}
	return f, nil
}

func (s *clientStream) release() {
	s.cc.mu.Lock()
	delete(s.cc.streams, s.id)
	s.cc.mu.Unlock()
}

// sendData sends p respecting the server's window.
func (s *clientStream) sendData(p []byte) error {
	for len(p) > 0 {
		n, err := s.stdinWin.take(min(len(p), chunkSize))
		if err != nil {
			return errConnLost
		}
		if err := s.cc.send(fStdin, s.id, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// Client talks to a paired server over one connection that is re-established when it drops.
type Client struct {
	Addr, Dir    string
	ReconnectFor time.Duration // how long a durable call keeps retrying (default 5 minutes)

	mu sync.Mutex
	cc *clientConn
}

func (c *Client) conn() (*clientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil && !c.cc.isDead() {
		return c.cc, nil
	}
	tc, err := dialKnown(c.Addr, c.Dir)
	if err != nil {
		return nil, err
	}
	c.cc = newClientConn(tc)
	return c.cc, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil {
		c.cc.close()
	}
}

func (c *Client) reconnectWindow() time.Duration {
	if c.ReconnectFor > 0 {
		return c.ReconnectFor
	}
	return 5 * time.Minute
}

// open dials if needed and opens a stream.
func (c *Client) open(req openReq) (*clientStream, error) {
	cc, err := c.conn()
	if err != nil {
		return nil, err
	}
	return cc.open(req)
}

func decodeErr(f frame) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(f.payload, &e)
	if e.Error == "" {
		e.Error = "remote error"
	}
	return errors.New(e.Error)
}

// Ping round-trips one request.
func (c *Client) Ping(ctx context.Context) error {
	s, err := c.open(openReq{Method: "ping"})
	if err != nil {
		return err
	}
	defer s.release()
	f, err := s.recv()
	if err != nil {
		return err
	}
	if f.typ == fError {
		return decodeErr(f)
	}
	return nil
}

type ExecOpts struct {
	Executable string
	Args       []string
	Cwd        string
	Env        []string
	Timeout    time.Duration
	Stdin      io.Reader // nil: no stdin. A call with stdin cannot survive a disconnect.
	Stdout     io.Writer
	Stderr     io.Writer
	Durable    bool   // survive disconnects: reconnect and resume, never running the command twice
	JobID      string // idempotency key for Durable calls (generated when empty)
	Keep       bool   // Durable: keep running while no client is attached (otherwise killed after a grace period)
	// Wait > 0 stops waiting after that long: the result has Running set and the job keeps running on the
	// server (requires Durable and Keep). Continue with Attach.
	Wait          time.Duration
	DetachOnStart bool // return as soon as the command has started (like Wait, but immediately)
	OnStart       func()
}

type ExecResult struct {
	ExitCode int
	Error    string // "canceled", "timeout", ... when the command was stopped rather than finished
	Running  bool   // the client stopped waiting (Wait / DetachOnStart); the job is still running
	Job      string // job id, for Attach / Kill
}

// detachPlan says when drain stops waiting without ending the job.
type detachPlan struct {
	at      time.Time // zero: never
	onStart bool
}

// Exec runs a command remotely. Context cancellation kills the remote process tree.
func (c *Client) Exec(ctx context.Context, o ExecOpts) (ExecResult, error) {
	job := ""
	if o.Durable && o.Stdin == nil {
		if job = o.JobID; job == "" {
			job = shortID()
		}
	}
	if (o.Wait > 0 || o.DetachOnStart) && (job == "" || !o.Keep) {
		return ExecResult{}, errors.New("wait/detach needs a durable job with Keep and without stdin")
	}
	plan := detachPlan{onStart: o.DetachOnStart}
	if o.Wait > 0 {
		plan.at = time.Now().Add(o.Wait)
	}
	return c.follow(ctx, job, o.Stdout, o.Stderr, plan, true, o.OnStart, func(nOut, nErr int64, first bool) openReq {
		return openReq{Method: "exec", Job: job, Executable: o.Executable, Args: o.Args, Cwd: o.Cwd, Env: o.Env,
			TimeoutMS: int(o.Timeout / time.Millisecond), Stdin: o.Stdin != nil, Keep: o.Keep, OutOffset: nOut, ErrOffset: nErr}
	}, o.Stdin)
}

type AttachOpts struct {
	Job            string
	All            bool          // replay all retained output instead of only what was not delivered yet
	Wait           time.Duration // > 0: stop waiting after this long (the job keeps running)
	Stdout, Stderr io.Writer
}

// Attach follows the output of a job started earlier (by Exec with Keep, `eco start` or `eco run --wait`)
// until it ends or Wait elapses. Cancelling the context detaches; it never kills the job (use Kill).
func (c *Client) Attach(ctx context.Context, o AttachOpts) (ExecResult, error) {
	plan := detachPlan{}
	if o.Wait > 0 {
		plan.at = time.Now().Add(o.Wait)
	}
	return c.follow(ctx, o.Job, o.Stdout, o.Stderr, plan, false, nil, func(nOut, nErr int64, first bool) openReq {
		if first {
			return openReq{Method: "attach", Job: o.Job, Resume: !o.All, All: o.All}
		}
		return openReq{Method: "attach", Job: o.Job, OutOffset: nOut, ErrOffset: nErr}
	}, nil)
}

// follow opens a stream built by mkReq and copies its output, reconnecting (with the offsets received so
// far) while the connection drops, as long as the call has a job id.
func (c *Client) follow(ctx context.Context, job string, out, errw io.Writer, plan detachPlan, cancelKills bool,
	onStart func(), mkReq func(nOut, nErr int64, first bool) openReq, stdin io.Reader) (ExecResult, error) {
	if out == nil {
		out = io.Discard
	}
	if errw == nil {
		errw = io.Discard
	}
	var nOut, nErr int64
	var lostSince time.Time
	started, first := false, true
	backoff := 100 * time.Millisecond
	for {
		s, err := c.open(mkReq(nOut, nErr, first))
		if err == nil {
			if stdin != nil {
				go pumpStdin(s, stdin)
			}
			var res ExecResult
			res, err = drain(ctx, s, &nOut, &nErr, out, errw, plan, cancelKills, func() {
				first = false
				if !started {
					started = true
					if onStart != nil {
						onStart()
					}
				}
			})
			s.release()
			if err == nil {
				res.Job = job
				if res.Running {
					return res, nil
				}
				if !cancelKills && ctx.Err() != nil { // attach interrupted: detached, the job goes on
					return ExecResult{Running: true, Job: job}, nil
				}
				return res, ctx.Err()
			}
		}
		if job == "" || !isTransient(err) {
			return ExecResult{Job: job}, err
		}
		if lostSince.IsZero() {
			lostSince = time.Now()
		}
		if time.Since(lostSince) > c.reconnectWindow() || ctx.Err() != nil {
			return ExecResult{}, fmt.Errorf("giving up reconnecting: %w", err)
		}
		select {
		case <-ctx.Done():
			return ExecResult{}, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func isTransient(err error) bool {
	if errors.Is(err, errConnLost) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "i/o timeout")
}

func pumpStdin(s *clientStream, r io.Reader) {
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if s.sendData(buf[:n]) != nil {
				return
			}
		}
		if err != nil {
			_ = s.cc.send(fStdinEOF, s.id, nil)
			return
		}
	}
}

// drain copies a stream's output until the exit status arrives, or until the client detaches (plan, or a
// cancelled context when cancelKills is false), which leaves the job running.
func drain(ctx context.Context, s *clientStream, nOut, nErr *int64, out, errw io.Writer, plan detachPlan, cancelKills bool, onStart func()) (ExecResult, error) {
	var mu sync.Mutex
	started, want, sent := false, false, false
	detach := func() { // only once the job is attached on the server, i.e. after the start meta
		mu.Lock()
		defer mu.Unlock()
		want = true
		if started && !sent {
			sent = true
			_ = s.cc.send(fDetach, s.id, nil)
		}
	}
	var stop func() bool
	if cancelKills {
		stop = context.AfterFunc(ctx, func() { _ = s.cc.send(fCancel, s.id, nil) })
	} else {
		stop = context.AfterFunc(ctx, detach)
	}
	defer stop()
	if !plan.at.IsZero() {
		t := time.AfterFunc(time.Until(plan.at), detach)
		defer t.Stop()
	}
	for {
		f, err := s.recv()
		if err != nil {
			return ExecResult{}, err
		}
		switch f.typ {
		case fMeta:
			var m metaInfo
			_ = json.Unmarshal(f.payload, &m)
			if m.Detached {
				return ExecResult{Running: true}, nil
			}
			if m.Started {
				*nOut, *nErr = m.Offsets[0], m.Offsets[1]
				if m.Dropped > 0 {
					fmt.Fprintf(errw, "[eco: %d bytes of earlier output were no longer retained]\n", m.Dropped)
				}
				onStart()
				mu.Lock()
				started = true
				mu.Unlock()
				if plan.onStart {
					detach()
				} else {
					mu.Lock()
					w := want
					mu.Unlock()
					if w {
						detach()
					}
				}
			}
		case fOut:
			if _, err := out.Write(f.payload); err != nil {
				return ExecResult{}, err
			}
			*nOut += int64(len(f.payload))
		case fErr:
			if _, err := errw.Write(f.payload); err != nil {
				return ExecResult{}, err
			}
			*nErr += int64(len(f.payload))
		case fExit:
			var e exitInfo
			_ = json.Unmarshal(f.payload, &e)
			return ExecResult{ExitCode: e.ExitCode, Error: e.Error}, nil
		case fError:
			return ExecResult{}, decodeErr(f)
		}
	}
}

// Put uploads a local file. The server writes to a temporary file and renames it after verifying size and SHA-256.
func (c *Client) Put(ctx context.Context, local, remote string) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	return c.putFrom(ctx, f, &size, uint32(st.Mode().Perm()), remote)
}

// Write stores everything read from r as the remote file (atomic, SHA-256 verified). The size need not be
// known in advance, so r can be stdin.
func (c *Client) Write(ctx context.Context, r io.Reader, remote string) error {
	return c.putFrom(ctx, r, nil, 0644, remote)
}

func (c *Client) putFrom(ctx context.Context, f io.Reader, size *int64, mode uint32, remote string) error {
	s, err := c.open(openReq{Method: "put", Path: remote, Mode: mode, Size: size})
	if err != nil {
		return err
	}
	defer s.release()
	stop := context.AfterFunc(ctx, func() { _ = s.cc.send(fCancel, s.id, nil) })
	defer stop()
	h := sha256.New()
	sendErr := make(chan error, 1)
	go func() {
		buf := make([]byte, chunkSize)
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				if err := s.sendData(buf[:n]); err != nil {
					sendErr <- err
					return
				}
			}
			if rerr == io.EOF {
				sendErr <- s.cc.send(fStdinEOF, s.id, mustJSON(map[string]string{"sha256": hex.EncodeToString(h.Sum(nil))}))
				return
			}
			if rerr != nil {
				sendErr <- rerr
				return
			}
		}
	}()
	for {
		fr, err := s.recv()
		if err != nil {
			return err
		}
		switch fr.typ {
		case fExit:
			return ctx.Err()
		case fError:
			return decodeErr(fr)
		}
	}
}

// Get downloads a remote file, resuming from local+".eco-part" if present, and verifies the SHA-256.
func (c *Client) Get(ctx context.Context, remote, local string) error {
	part := local + ".eco-part"
	var offset int64
	if st, err := os.Stat(part); err == nil {
		offset = st.Size()
	}
	if err := os.MkdirAll(filepath.Dir(local), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
	}()
	s, err := c.open(openReq{Method: "get", Path: remote, Offset: offset})
	if err != nil {
		return err
	}
	defer s.release()
	stop := context.AfterFunc(ctx, func() { _ = s.cc.send(fCancel, s.id, nil) })
	defer stop()
	var mode os.FileMode = 0644
	for {
		fr, err := s.recv()
		if err != nil {
			return err
		}
		switch fr.typ {
		case fMeta:
			var m metaInfo
			_ = json.Unmarshal(fr.payload, &m)
			if m.Mode != 0 {
				mode = os.FileMode(m.Mode)
			}
		case fOut:
			if _, err := f.Write(fr.payload); err != nil {
				return err
			}
		case fError:
			return decodeErr(fr)
		case fExit:
			var e exitInfo
			_ = json.Unmarshal(fr.payload, &e)
			if err := f.Close(); err != nil {
				return err
			}
			closed = true
			sum, err := fileSHA256(part)
			if err != nil {
				return err
			}
			if e.SHA256 != "" && sum != e.SHA256 {
				os.Remove(part) // a corrupt partial must not be resumed
				return errors.New("checksum mismatch; partial file discarded")
			}
			_ = os.Chmod(part, mode)
			if err := os.Rename(part, local); err != nil {
				return err
			}
			return ctx.Err()
		}
	}
}

// Cat writes a remote file to w and verifies its SHA-256 (reported as an error after the data was written).
func (c *Client) Cat(ctx context.Context, remote string, w io.Writer) error {
	s, err := c.open(openReq{Method: "get", Path: remote})
	if err != nil {
		return err
	}
	defer s.release()
	stop := context.AfterFunc(ctx, func() { _ = s.cc.send(fCancel, s.id, nil) })
	defer stop()
	h := sha256.New()
	for {
		fr, err := s.recv()
		if err != nil {
			return err
		}
		switch fr.typ {
		case fOut:
			h.Write(fr.payload)
			if _, err := w.Write(fr.payload); err != nil {
				_ = s.cc.send(fCancel, s.id, nil)
				return err
			}
		case fError:
			return decodeErr(fr)
		case fExit:
			var e exitInfo
			_ = json.Unmarshal(fr.payload, &e)
			if e.SHA256 != "" && hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
				return errors.New("checksum mismatch")
			}
			return ctx.Err()
		}
	}
}

// call runs a request that answers with optional data frames and an exit, returning the data.
func (c *Client) call(req openReq) ([]byte, error) {
	s, err := c.open(req)
	if err != nil {
		return nil, err
	}
	defer s.release()
	var out []byte
	for {
		f, err := s.recv()
		if err != nil {
			return nil, err
		}
		switch f.typ {
		case fOut:
			out = append(out, f.payload...)
		case fError:
			return nil, decodeErr(f)
		case fExit:
			return out, nil
		}
	}
}

// Jobs lists the jobs this client has on the server (running, and finished ones still retained).
func (c *Client) Jobs() ([]jobInfo, error) {
	b, err := c.call(openReq{Method: "jobs"})
	if err != nil {
		return nil, err
	}
	var list []jobInfo
	return list, json.Unmarshal(b, &list)
}

// Kill stops a job and its whole process tree.
func (c *Client) Kill(id string) error {
	_, err := c.call(openReq{Method: "kill", Job: id})
	return err
}

// Forward listens on listen and relays every connection to target, a host:port reachable from the server
// (like ssh -L). It returns when ctx is cancelled.
func (c *Client) Forward(ctx context.Context, listen, target string, logw io.Writer) error {
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	fmt.Fprintf(logw, "forwarding %s -> %s (on the server)\n", l.Addr(), target)
	for {
		lc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			if err := c.forwardConn(lc, target); err != nil {
				fmt.Fprintf(logw, "forward %s: %v\n", target, err)
			}
		}()
	}
}

func (c *Client) forwardConn(lc net.Conn, target string) error {
	defer lc.Close()
	s, err := c.open(openReq{Method: "dial", Target: target})
	if err != nil {
		return err
	}
	defer s.release()
	f, err := s.recv()
	if err != nil {
		return err
	}
	if f.typ == fError {
		return decodeErr(f)
	}
	go func() { // local -> server
		buf := make([]byte, chunkSize)
		for {
			n, rerr := lc.Read(buf)
			if n > 0 && s.sendData(buf[:n]) != nil {
				return
			}
			if rerr == io.EOF {
				_ = s.cc.send(fStdinEOF, s.id, nil)
				return
			}
			if rerr != nil {
				_ = s.cc.send(fCancel, s.id, nil)
				return
			}
		}
	}()
	for { // server -> local
		f, err := s.recv()
		if err != nil {
			return err
		}
		switch f.typ {
		case fOut:
			if _, err := lc.Write(f.payload); err != nil {
				_ = s.cc.send(fCancel, s.id, nil)
				return nil
			}
		case fExit:
			return nil
		case fError:
			return decodeErr(f)
		}
	}
}

// shortID is a job id that is easy to type: 8 hex digits.
func shortID() string { return randomID()[:8] }

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
