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
	OnStart    func()
}

type ExecResult struct {
	ExitCode int
	Error    string // "canceled", "timeout", ... when the command was stopped rather than finished
}

// Exec runs a command remotely. Context cancellation kills the remote process tree.
func (c *Client) Exec(ctx context.Context, o ExecOpts) (ExecResult, error) {
	job := ""
	if o.Durable && o.Stdin == nil {
		if job = o.JobID; job == "" {
			job = randomID()
		}
	}
	out, errw := o.Stdout, o.Stderr
	if out == nil {
		out = io.Discard
	}
	if errw == nil {
		errw = io.Discard
	}
	var nOut, nErr int64
	var lostSince time.Time
	started := false
	backoff := 100 * time.Millisecond
	for attempt := 0; ; attempt++ {
		req := openReq{Method: "exec", Job: job, Executable: o.Executable, Args: o.Args, Cwd: o.Cwd, Env: o.Env,
			TimeoutMS: int(o.Timeout / time.Millisecond), Stdin: o.Stdin != nil, OutOffset: nOut, ErrOffset: nErr}
		s, err := c.open(req)
		if err == nil {
			if o.Stdin != nil {
				go pumpStdin(s, o.Stdin)
			}
			var res ExecResult
			res, err = drain(ctx, s, &nOut, &nErr, out, errw, func() {
				if !started {
					started = true
					if o.OnStart != nil {
						o.OnStart()
					}
				}
			})
			s.release()
			if err == nil {
				return res, ctx.Err()
			}
		}
		if job == "" || !isTransient(err) {
			return ExecResult{}, err
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

// drain copies a stream's output until the exit status arrives.
func drain(ctx context.Context, s *clientStream, nOut, nErr *int64, out, errw io.Writer, onStart func()) (ExecResult, error) {
	stop := context.AfterFunc(ctx, func() { _ = s.cc.send(fCancel, s.id, nil) })
	defer stop()
	for {
		f, err := s.recv()
		if err != nil {
			return ExecResult{}, err
		}
		switch f.typ {
		case fMeta:
			onStart()
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
	s, err := c.open(openReq{Method: "put", Path: remote, Mode: uint32(st.Mode().Perm()), Size: &size})
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
