package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ringCap        = 16 << 20 // output retained per stream of a job, for resuming after a disconnect
	maxJobsPerPeer = 256
	maxTimeout     = 24 * time.Hour
)

// openReq starts a stream. Method is one of exec, attach, jobs, kill, put, get, dial, ping (pair is handled
// before the mux).
type openReq struct {
	Method string `json:"method"`
	Name   string `json:"name,omitempty"` // pair: label of the client

	// exec / attach / kill
	Job        string   `json:"job,omitempty"` // client-chosen idempotency key; makes the job survive disconnects
	Executable string   `json:"executable,omitempty"`
	Args       []string `json:"args,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Env        []string `json:"env,omitempty"` // extra KEY=VALUE entries
	TimeoutMS  int      `json:"timeout_ms,omitempty"`
	Stdin      bool     `json:"stdin,omitempty"`
	Keep       bool     `json:"keep,omitempty"`       // keep running while no client is attached, until it ends
	OutOffset  int64    `json:"out_offset,omitempty"` // bytes of stdout the client already has
	ErrOffset  int64    `json:"err_offset,omitempty"`
	Resume     bool     `json:"resume,omitempty"` // attach: continue after the output already delivered
	All        bool     `json:"all,omitempty"`    // attach: replay all retained output

	// put / get
	Path   string `json:"path,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	Size   *int64 `json:"size,omitempty"`   // put: expected size
	Offset int64  `json:"offset,omitempty"` // get: resume position

	// dial
	Target string `json:"target,omitempty"` // host:port reachable from the server
}

type exitInfo struct {
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

type metaInfo struct {
	Started   bool     `json:"started,omitempty"`
	Job       string   `json:"job,omitempty"`
	Size      int64    `json:"size,omitempty"`
	Mode      uint32   `json:"mode,omitempty"`
	Offsets   [2]int64 `json:"offsets,omitempty"` // attach: absolute stdout/stderr offsets output resumes at
	Dropped   int64    `json:"dropped,omitempty"` // attach: bytes that were no longer retained
	Detached  bool     `json:"detached,omitempty"`
	Delivered [2]int64 `json:"delivered,omitempty"` // detached: offsets the client has received
}

// jobInfo describes a retained job for `eco jobs`.
type jobInfo struct {
	ID       string    `json:"id"`
	Command  string    `json:"command"`
	Cwd      string    `json:"cwd,omitempty"`
	Running  bool      `json:"running"`
	Attached bool      `json:"attached"`
	ExitCode int       `json:"exit_code"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended,omitzero"`
	Unread   int64     `json:"unread"` // output bytes not yet delivered to any client
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func sendErrFrame(w io.Writer, id uint32, msg string) {
	_ = writeFrame(w, fError, id, mustJSON(map[string]string{"error": msg}))
}

// ---------- output ring ----------

type chunk struct {
	off int64
	b   []byte
}

// ring keeps the most recent bytes of one output stream, addressed by absolute offsets.
type ring struct {
	chunks     []chunk
	start, end int64
	cap        int64
}

func (r *ring) append(p []byte) {
	for len(p) > 0 {
		if n := len(r.chunks); n > 0 && len(r.chunks[n-1].b) < chunkSize {
			k := min(chunkSize-len(r.chunks[n-1].b), len(p))
			r.chunks[n-1].b = append(r.chunks[n-1].b, p[:k]...)
			p = p[k:]
			r.end += int64(k)
			continue
		}
		k := min(chunkSize, len(p))
		b := make([]byte, k, chunkSize)
		copy(b, p[:k])
		r.chunks = append(r.chunks, chunk{off: r.end, b: b})
		p = p[k:]
		r.end += int64(k)
	}
	for r.end-r.start > r.cap && len(r.chunks) > 1 {
		r.chunks[0] = chunk{}
		r.chunks = r.chunks[1:]
		r.start = r.chunks[0].off
	}
}

// read copies up to max bytes starting at off (start <= off < end).
func (r *ring) read(off int64, max int) []byte {
	if off < r.start || off >= r.end {
		return nil
	}
	i := sort.Search(len(r.chunks), func(i int) bool { return r.chunks[i].off+int64(len(r.chunks[i].b)) > off })
	c := r.chunks[i]
	from := off - c.off
	k := min(int64(max), int64(len(c.b))-from)
	return append([]byte(nil), c.b[from:from+k]...)
}

// ---------- jobs ----------

type attachment struct {
	s      *serverStream
	next   [2]int64
	closed bool
	done   chan struct{} // closed when the pump goroutine returns
}

type job struct {
	m       *muxServer
	key     string
	durable bool
	req     openReq
	ready   chan struct{}
	startEr error
	begin   time.Time

	busy   atomic.Int32 // output readers currently storing data
	lastIO atomic.Int64 // unix nanoseconds of the last output read

	mu        sync.Mutex
	cond      *sync.Cond
	rings     [2]*ring // 0 stdout, 1 stderr
	sent      [2]int64
	delivered [2]int64 // output confirmed received by a client (where `eco attach` resumes)
	att       *attachment
	done      bool
	exit      exitInfo
	end       time.Time
	killed    string
	started   bool
	cmd       *exec.Cmd
	stdinW    io.WriteCloser
	grace     *time.Timer
	timeout   *time.Timer
}

func newJob(m *muxServer, key string, req openReq) *job {
	j := &job{m: m, key: key, durable: req.Job != "", req: req, ready: make(chan struct{}), begin: time.Now()}
	j.cond = sync.NewCond(&j.mu)
	j.rings = [2]*ring{{cap: ringCap}, {cap: ringCap}}
	return j
}

// write stores process output. While a client is attached it applies backpressure to the process; while
// nobody is attached the oldest output is dropped instead, so a detached job never blocks.
func (j *job) write(i int, p []byte) {
	j.mu.Lock()
	for j.att != nil && j.killed == "" && (j.rings[i].end-j.sent[i])+int64(len(p)) > ringCap-initialWindow {
		j.cond.Wait()
	}
	j.rings[i].append(p)
	j.cond.Broadcast()
	j.mu.Unlock()
}

func (j *job) kill(reason string) {
	j.mu.Lock()
	if j.done {
		j.mu.Unlock()
		return
	}
	if j.killed == "" {
		j.killed = reason
	}
	started, cmd, in := j.started, j.cmd, j.stdinW
	j.cond.Broadcast()
	j.mu.Unlock()
	if in != nil {
		_ = in.Close()
	}
	if started {
		killTree(cmd)
	}
}

// run collects the output and the exit status. The command counts as finished when its process exits:
// programs it started in the background (Start-Process, `cmd &`, daemons) may inherit the output pipes
// and keep them open for hours, so after the exit the pipes are drained only until they go quiet for
// outputGrace and are then closed.
func (j *job) run(stdout, stderr *os.File) {
	readers := make(chan struct{})
	var wg sync.WaitGroup
	for i, r := range []*os.File{stdout, stderr} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, chunkSize)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					j.busy.Add(1)
					j.write(i, buf[:n])
					j.lastIO.Store(time.Now().UnixNano())
					j.busy.Add(-1)
				}
				if err != nil {
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(readers) }()
	err := j.cmd.Wait() // Stdout/Stderr are *os.File, so this returns as soon as the process exits
	exited := time.Now()
	j.lastIO.Store(exited.UnixNano())
	tick := time.NewTicker(min(j.m.outputGrace/4, 100*time.Millisecond))
drain:
	for {
		select {
		case <-readers:
			break drain
		case <-tick.C:
			// Output still being stored (a slow client applying backpressure) is never cut. Otherwise stop when
			// the pipes are quiet, or after a few grace periods if a background process keeps writing to them.
			quiet := time.Since(time.Unix(0, j.lastIO.Load())) >= j.m.outputGrace
			if j.busy.Load() == 0 && (quiet || time.Since(exited) >= 5*j.m.outputGrace) {
				break drain
			}
		}
	}
	tick.Stop()
	stdout.Close() // unblocks readers still waiting on pipes held open by background processes
	stderr.Close()
	<-readers
	e := exitInfo{ExitCode: j.cmd.ProcessState.ExitCode()}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		e.Error = err.Error()
	}
	j.mu.Lock()
	if j.killed != "" {
		e.Error = j.killed
	}
	j.done, j.exit, j.end = true, e, time.Now()
	if j.grace != nil {
		j.grace.Stop()
	}
	if j.timeout != nil {
		j.timeout.Stop()
	}
	j.cond.Broadcast()
	j.mu.Unlock()
}

// attach binds a stream to the job and starts replaying output from the client's offsets.
func (j *job) attach(s *serverStream, off [2]int64, meta metaInfo) error {
	meta.Started, meta.Offsets = true, off
	j.mu.Lock()
	for i := 0; i < 2; i++ {
		if off[i] < j.rings[i].start {
			j.mu.Unlock()
			return errors.New("output expired: the job produced more output than is retained while no client was attached")
		}
		if off[i] > j.rings[i].end || off[i] < 0 {
			j.mu.Unlock()
			return errors.New("offset beyond the output of this job")
		}
	}
	old := j.att
	if old != nil {
		old.closed = true
	}
	att := &attachment{s: s, next: off, done: make(chan struct{})}
	j.att = att
	j.sent = off
	j.delivered = off
	if j.grace != nil {
		j.grace.Stop()
		j.grace = nil
	}
	j.cond.Broadcast()
	j.mu.Unlock()
	if old != nil {
		old.s.c.fail(old.s, "job attached by another stream")
	}
	s.mu.Lock()
	s.job, s.att = j, att
	s.mu.Unlock()
	// The start meta carries the offsets output resumes at, so it must precede the first output frame.
	_ = s.c.send(fMeta, s.id, mustJSON(meta))
	go j.pump(att)
	return nil
}

func (j *job) detach(att *attachment) {
	if att == nil {
		return
	}
	j.mu.Lock()
	att.closed = true
	if j.att == att {
		j.att = nil
		if !j.done && j.durable && !j.req.Keep && j.grace == nil {
			j.grace = time.AfterFunc(j.m.detachGrace, func() { j.kill("no client reattached in time") })
		}
	}
	j.cond.Broadcast()
	j.mu.Unlock()
}

// detachClean ends an attachment at the client's request: the pump is stopped first, so the offsets it
// reports are exactly what was sent before the reply, and the next `eco attach` continues from there.
func (j *job) detachClean(s *serverStream, att *attachment) {
	j.mu.Lock()
	att.closed = true
	j.cond.Broadcast()
	j.mu.Unlock()
	s.out.close() // wakes a pump waiting for credit
	<-att.done
	j.mu.Lock()
	delivered := att.next
	if j.att == att {
		j.delivered = delivered
	}
	j.mu.Unlock()
	j.detach(att)
	_ = s.c.send(fMeta, s.id, mustJSON(metaInfo{Detached: true, Delivered: delivered}))
	s.c.remove(s.id)
}

// pump streams ring contents and finally the exit status to the attached stream.
func (j *job) pump(att *attachment) {
	defer close(att.done)
	s := att.s
	for {
		j.mu.Lock()
		i := -1
		for {
			if att.closed {
				j.mu.Unlock()
				return
			}
			for k := 0; k < 2; k++ {
				if att.next[k] < j.rings[k].end {
					i = k
					break
				}
			}
			if i >= 0 {
				break
			}
			if j.done {
				e := j.exit
				if j.att == att {
					j.delivered = att.next
				}
				j.mu.Unlock()
				_ = s.c.send(fExit, s.id, mustJSON(e))
				s.c.remove(s.id)
				return
			}
			j.cond.Wait()
		}
		off := att.next[i]
		avail := j.rings[i].end - off
		j.mu.Unlock()

		n, err := s.out.take(int(min(avail, chunkSize)))
		if err != nil {
			return
		}
		j.mu.Lock()
		if att.closed {
			j.mu.Unlock()
			return
		}
		data := j.rings[i].read(off, n)
		j.mu.Unlock()
		if len(data) < n {
			s.out.add(int64(n - len(data)))
		}
		typ := fOut
		if i == 1 {
			typ = fErr
		}
		if err := s.c.send(typ, s.id, data); err != nil {
			return
		}
		j.mu.Lock()
		att.next[i] += int64(len(data))
		j.sent[i] = att.next[i]
		j.cond.Broadcast()
		j.mu.Unlock()
	}
}

// ---------- server ----------

type muxServer struct {
	mu          sync.Mutex
	jobs        map[string]*job
	perPeer     map[string]int
	detachGrace time.Duration // kill a durable job (without Keep) nobody reattaches to
	retain      time.Duration // how long finished jobs stay available for reattaching
	outputGrace time.Duration // after the process exits, how long quiet pipes are still drained
	stop        chan struct{}
}

func newMuxServer() *muxServer {
	m := &muxServer{jobs: map[string]*job{}, perPeer: map[string]int{}, detachGrace: 10 * time.Minute,
		retain: time.Hour, outputGrace: 500 * time.Millisecond, stop: make(chan struct{})}
	go m.janitor()
	return m
}

func (m *muxServer) close() { close(m.stop) }

func (m *muxServer) janitor() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.mu.Lock()
			for k, j := range m.jobs {
				j.mu.Lock()
				expired := j.done && time.Since(j.end) > m.retain
				j.mu.Unlock()
				if expired {
					delete(m.jobs, k)
					peer := k[:len(k)-len(j.req.Job)-1]
					if m.perPeer[peer]--; m.perPeer[peer] <= 0 {
						delete(m.perPeer, peer)
					}
				}
			}
			m.mu.Unlock()
		}
	}
}

type serverConn struct {
	m    *muxServer
	conn net.Conn
	fp   string
	wmu  sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*serverStream
	last    uint32
	closed  bool
}

type serverStream struct {
	id    uint32
	c     *serverConn
	out   *window      // credit for data sent to the client
	stdin *frameQueue  // stdin/upload frames from the client
	pend  atomic.Int64 // stdin bytes queued, to enforce the window

	mu     sync.Mutex
	job    *job
	att    *attachment
	cancel func()
}

func (c *serverConn) send(typ byte, id uint32, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := writeFrame(c.conn, typ, id, payload); err != nil {
		c.conn.Close()
		return err
	}
	return nil
}

func (c *serverConn) remove(id uint32) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

func (c *serverConn) fail(s *serverStream, msg string) {
	_ = c.send(fError, s.id, mustJSON(map[string]string{"error": msg}))
	c.remove(s.id)
}

// serveConn runs the multiplexed protocol for an authorized peer. first is a frame that was already read.
func (m *muxServer) serveConn(conn net.Conn, r io.Reader, fp string, first *frame) {
	c := &serverConn{m: m, conn: conn, fp: fp, streams: map[uint32]*serverStream{}}
	defer c.shutdown()
	for {
		var f frame
		if first != nil {
			f, first = *first, nil
		} else {
			var err error
			if f, err = readFrame(r); err != nil {
				return
			}
		}
		c.mu.Lock()
		s := c.streams[f.stream]
		c.mu.Unlock()
		switch f.typ {
		case fOpen:
			c.open(f)
		case fStdin, fStdinEOF:
			if s == nil || s.stdin == nil {
				continue
			}
			if s.pend.Add(int64(len(f.payload))) > 2*initialWindow {
				return // peer ignored flow control
			}
			s.stdin.push(f)
		case fCancel:
			if s != nil {
				s.mu.Lock()
				cancel := s.cancel
				s.mu.Unlock()
				if cancel != nil {
					cancel()
				}
			}
		case fCredit:
			if s != nil && len(f.payload) == 4 {
				s.out.add(int64(binary.BigEndian.Uint32(f.payload)))
			}
		case fDetach:
			if s != nil {
				s.mu.Lock()
				j, att := s.job, s.att
				s.mu.Unlock()
				if j != nil && att != nil {
					go j.detachClean(s, att)
				}
			}
		default:
			return
		}
	}
}

func (c *serverConn) shutdown() {
	c.conn.Close()
	c.mu.Lock()
	c.closed = true
	streams := make([]*serverStream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	c.mu.Unlock()
	for _, s := range streams {
		s.out.close()
		if s.stdin != nil {
			s.stdin.close(errClosed)
		}
		s.mu.Lock()
		j, att := s.job, s.att
		s.mu.Unlock()
		if j != nil {
			j.detach(att)
			if !j.durable {
				j.kill("connection closed")
			}
		}
	}
}

func (c *serverConn) open(f frame) {
	var req openReq
	c.mu.Lock()
	if c.closed || f.stream <= c.last || c.streams[f.stream] != nil {
		c.mu.Unlock()
		sendErrFrame(c.conn, f.stream, "invalid stream id")
		return
	}
	c.last = f.stream
	s := &serverStream{id: f.stream, c: c, out: newWindow(initialWindow)}
	c.streams[f.stream] = s
	c.mu.Unlock()
	if err := json.Unmarshal(f.payload, &req); err != nil {
		c.fail(s, "invalid request")
		return
	}
	switch req.Method {
	case "ping":
		_ = c.send(fExit, s.id, mustJSON(exitInfo{}))
		c.remove(s.id)
	case "exec":
		if req.Stdin { // before the next frame is read, so early stdin data is never dropped
			s.stdin = newFrameQueue()
		}
		go c.execStream(s, req)
	case "attach":
		go c.attachStream(s, req)
	case "jobs":
		go c.jobsStream(s)
	case "kill":
		go c.killStream(s, req)
	case "put":
		s.stdin = newFrameQueue()
		go c.putStream(s, req)
	case "get":
		go c.getStream(s, req)
	case "dial":
		s.stdin = newFrameQueue()
		go c.dialStream(s, req)
	default:
		c.fail(s, "unknown method")
	}
}

// stdinCredit returns flow-control credit to the client once data has been consumed.
func (s *serverStream) stdinCredit() *creditor {
	return &creditor{grant: func(n int) { _ = s.c.send(fCredit, s.id, creditPayload(n)) }}
}

func (c *serverConn) execStream(s *serverStream, req openReq) {
	if req.Executable == "" || req.TimeoutMS < 0 || time.Duration(req.TimeoutMS)*time.Millisecond > maxTimeout {
		c.fail(s, "invalid executable or timeout_ms")
		return
	}
	if req.Stdin && req.Job != "" {
		c.fail(s, "stdin cannot be used with a durable job")
		return
	}
	j, fresh, err := c.m.acquire(c.fp, req)
	if err != nil {
		c.fail(s, err.Error())
		return
	}
	<-j.ready
	if j.startEr != nil {
		c.fail(s, j.startEr.Error())
		return
	}
	s.mu.Lock()
	s.cancel = func() { j.kill("canceled") }
	s.mu.Unlock()
	if req.Stdin {
		go c.stdinLoop(s, j)
	}
	if err := j.attach(s, [2]int64{req.OutOffset, req.ErrOffset}, metaInfo{Job: req.Job}); err != nil {
		if fresh && !j.durable {
			j.kill("canceled")
		}
		c.fail(s, err.Error())
	}
}

// lookup returns a retained job of this client.
func (c *serverConn) lookup(id string) *job {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	return c.m.jobs[c.fp+"|"+id]
}

// attachStream streams the output of an existing job: by default only what no client has received yet.
func (c *serverConn) attachStream(s *serverStream, req openReq) {
	j := c.lookup(req.Job)
	if req.Job == "" || j == nil {
		c.fail(s, "no such job: "+req.Job+" (see `eco jobs`)")
		return
	}
	<-j.ready
	if j.startEr != nil {
		c.fail(s, j.startEr.Error())
		return
	}
	j.mu.Lock()
	off := [2]int64{req.OutOffset, req.ErrOffset}
	switch {
	case req.All:
		off = [2]int64{j.rings[0].start, j.rings[1].start}
	case req.Resume:
		off = j.delivered
	}
	var dropped int64
	for i := range off {
		if off[i] < j.rings[i].start {
			dropped += j.rings[i].start - off[i]
			off[i] = j.rings[i].start
		}
	}
	j.mu.Unlock()
	s.mu.Lock()
	s.cancel = func() { j.kill("canceled") }
	s.mu.Unlock()
	if err := j.attach(s, off, metaInfo{Job: req.Job, Dropped: dropped}); err != nil {
		c.fail(s, err.Error())
	}
}

func (c *serverConn) jobsStream(s *serverStream) {
	c.m.mu.Lock()
	var list []jobInfo
	for key, j := range c.m.jobs {
		if key[:len(key)-len(j.req.Job)-1] != c.fp {
			continue
		}
		j.mu.Lock()
		cmd := strings.Join(append([]string{j.req.Executable}, j.req.Args...), " ")
		if len(cmd) > 300 {
			cmd = cmd[:300] + "..."
		}
		list = append(list, jobInfo{ID: j.req.Job, Command: cmd, Cwd: j.req.Cwd, Running: !j.done && j.startEr == nil,
			Attached: j.att != nil, ExitCode: j.exit.ExitCode, Error: j.exit.Error, Started: j.begin, Ended: j.end,
			Unread: (j.rings[0].end - j.delivered[0]) + (j.rings[1].end - j.delivered[1])})
		j.mu.Unlock()
	}
	c.m.mu.Unlock()
	sort.Slice(list, func(a, b int) bool { return list[a].Started.Before(list[b].Started) })
	for len(list) > 0 { // keep the reply within one frame
		b := mustJSON(list)
		if len(b) <= maxFrame {
			_ = c.send(fOut, s.id, b)
			break
		}
		list = list[len(list)/4+1:]
	}
	if len(list) == 0 {
		_ = c.send(fOut, s.id, []byte("[]"))
	}
	_ = c.send(fExit, s.id, mustJSON(exitInfo{}))
	c.remove(s.id)
}

func (c *serverConn) killStream(s *serverStream, req openReq) {
	j := c.lookup(req.Job)
	if req.Job == "" || j == nil {
		c.fail(s, "no such job: "+req.Job)
		return
	}
	j.kill("killed")
	_ = c.send(fExit, s.id, mustJSON(exitInfo{}))
	c.remove(s.id)
}

// dialStream forwards one TCP connection from the client to a target reachable from the server.
// Data goes both ways with flow control; the stream ends when the target closes its side.
func (c *serverConn) dialStream(s *serverStream, req openReq) {
	if req.Target == "" {
		c.fail(s, "target is required")
		return
	}
	conn, err := net.DialTimeout("tcp", req.Target, 10*time.Second)
	if err != nil {
		c.fail(s, err.Error())
		return
	}
	defer conn.Close()
	s.mu.Lock()
	s.cancel = func() { conn.Close() }
	s.mu.Unlock()
	_ = c.send(fMeta, s.id, mustJSON(metaInfo{Started: true}))
	go func() { // client -> target
		cr := s.stdinCredit()
		for {
			f, err := s.stdin.pop()
			if err != nil {
				conn.Close()
				return
			}
			if f.typ == fStdinEOF {
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				return
			}
			_, werr := conn.Write(f.payload)
			s.pend.Add(-int64(len(f.payload)))
			cr.consume(len(f.payload))
			if werr != nil {
				conn.Close()
				return
			}
		}
	}()
	buf := make([]byte, chunkSize)
	for { // target -> client
		n, err := s.out.take(chunkSize)
		if err != nil {
			s.stdin.close(errClosed)
			c.remove(s.id)
			return
		}
		k, rerr := conn.Read(buf[:n])
		if k < n {
			s.out.add(int64(n - k))
		}
		if k > 0 {
			if err := c.send(fOut, s.id, buf[:k]); err != nil {
				return
			}
		}
		if rerr != nil {
			s.stdin.close(errClosed)
			_ = c.send(fExit, s.id, mustJSON(exitInfo{}))
			c.remove(s.id)
			return
		}
	}
}

// stdinLoop copies client stdin frames into the process.
func (c *serverConn) stdinLoop(s *serverStream, j *job) {
	cr := s.stdinCredit()
	for {
		f, err := s.stdin.pop()
		if err != nil {
			_ = j.stdinW.Close()
			return
		}
		if f.typ == fStdinEOF {
			_ = j.stdinW.Close()
			return
		}
		_, werr := j.stdinW.Write(f.payload)
		s.pend.Add(-int64(len(f.payload)))
		cr.consume(len(f.payload))
		if werr != nil {
			// The process closed its stdin; drain silently so the client is not blocked.
			for {
				f, err := s.stdin.pop()
				if err != nil || f.typ == fStdinEOF {
					return
				}
				cr.consume(len(f.payload))
			}
		}
	}
}

// acquire returns the job for req, starting it unless an identical durable job already exists.
func (m *muxServer) acquire(fp string, req openReq) (*job, bool, error) {
	key := fp + "|" + req.Job
	m.mu.Lock()
	if req.Job != "" {
		if j, ok := m.jobs[key]; ok {
			m.mu.Unlock()
			if j.req.Executable != req.Executable || fmt.Sprint(j.req.Args) != fmt.Sprint(req.Args) || j.req.Cwd != req.Cwd {
				return nil, false, errors.New("job id already used for a different command")
			}
			return j, false, nil
		}
		if m.perPeer[fp] >= maxJobsPerPeer {
			m.mu.Unlock()
			return nil, false, errors.New("too many retained jobs for this client")
		}
	}
	j := newJob(m, key, req)
	if req.Job != "" {
		m.jobs[key] = j
		m.perPeer[fp]++
	}
	m.mu.Unlock()
	m.start(j)
	if j.startEr != nil && req.Job != "" {
		m.mu.Lock()
		delete(m.jobs, key)
		if m.perPeer[fp]--; m.perPeer[fp] <= 0 {
			delete(m.perPeer, fp)
		}
		m.mu.Unlock()
	}
	return j, true, nil
}

func (m *muxServer) start(j *job) {
	defer close(j.ready)
	req := j.req
	cmd := exec.Command(req.Executable, req.Args...)
	cmd.Dir = req.Cwd
	if len(req.Env) > 0 {
		cmd.Env = append(os.Environ(), req.Env...)
	}
	prepareCmd(cmd)
	// Own pipes instead of StdoutPipe: cmd.Wait must not wait for the pipes to close (see run).
	outR, outW, err := os.Pipe()
	if err != nil {
		j.startEr = err
		return
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		j.startEr = err
		return
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	fail := func(err error) {
		for _, f := range []*os.File{outR, outW, errR, errW} {
			f.Close()
		}
		j.startEr = err
	}
	if req.Stdin {
		if j.stdinW, err = cmd.StdinPipe(); err != nil {
			fail(err)
			return
		}
	}
	if err := cmd.Start(); err != nil {
		fail(err)
		return
	}
	outW.Close() // the child has its own copies
	errW.Close()
	j.mu.Lock()
	j.cmd, j.started = cmd, true
	pending := j.killed
	if req.TimeoutMS > 0 {
		j.timeout = time.AfterFunc(time.Duration(req.TimeoutMS)*time.Millisecond, func() { j.kill("timeout") })
	}
	j.mu.Unlock()
	go j.run(outR, errR)
	if pending != "" {
		killTree(cmd)
	}
}

// ---------- file transfer ----------

func (c *serverConn) putStream(s *serverStream, req openReq) {
	if req.Path == "" {
		c.fail(s, "path is required")
		return
	}
	mode := os.FileMode(req.Mode & 0777)
	if mode == 0 {
		mode = 0644
	}
	if err := os.MkdirAll(filepath.Dir(req.Path), 0755); err != nil {
		c.fail(s, err.Error())
		return
	}
	tmp := req.Path + ".eco-part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		c.fail(s, err.Error())
		return
	}
	s.mu.Lock()
	s.cancel = func() { s.stdin.close(errors.New("canceled")) }
	s.mu.Unlock()
	abort := func(msg string) {
		f.Close()
		os.Remove(tmp)
		c.fail(s, msg)
	}
	h := sha256.New()
	var total int64
	cr := s.stdinCredit()
	for {
		fr, err := s.stdin.pop()
		if err != nil {
			f.Close()
			os.Remove(tmp)
			c.fail(s, "canceled")
			return
		}
		if fr.typ == fStdin {
			if _, err := f.Write(fr.payload); err != nil {
				abort(err.Error())
				return
			}
			h.Write(fr.payload)
			total += int64(len(fr.payload))
			s.pend.Add(-int64(len(fr.payload)))
			cr.consume(len(fr.payload))
			continue
		}
		var tail struct {
			SHA256 string `json:"sha256"`
		}
		_ = json.Unmarshal(fr.payload, &tail)
		sum := hex.EncodeToString(h.Sum(nil))
		switch {
		case req.Size != nil && *req.Size != total:
			abort(fmt.Sprintf("size mismatch: expected %d bytes, received %d", *req.Size, total))
		case tail.SHA256 != "" && tail.SHA256 != sum:
			abort("checksum mismatch")
		default:
			if err := f.Close(); err != nil {
				os.Remove(tmp)
				c.fail(s, err.Error())
			} else if err := os.Rename(tmp, req.Path); err != nil {
				os.Remove(tmp)
				c.fail(s, err.Error())
			} else {
				_ = c.send(fExit, s.id, mustJSON(exitInfo{SHA256: sum, Size: total}))
				c.remove(s.id)
			}
		}
		return
	}
}

func (c *serverConn) getStream(s *serverStream, req openReq) {
	f, err := os.Open(req.Path)
	if err != nil {
		c.fail(s, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		c.fail(s, "not a regular file")
		return
	}
	if req.Offset < 0 || req.Offset > st.Size() {
		c.fail(s, "offset beyond end of file")
		return
	}
	s.mu.Lock()
	s.cancel = func() { s.out.close() }
	s.mu.Unlock()
	h := sha256.New()
	if req.Offset > 0 { // the digest always covers the whole file, so a resumed download can be verified
		if _, err := io.CopyN(h, f, req.Offset); err != nil {
			c.fail(s, err.Error())
			return
		}
	}
	_ = c.send(fMeta, s.id, mustJSON(metaInfo{Size: st.Size(), Mode: uint32(st.Mode().Perm())}))
	buf := make([]byte, chunkSize)
	for {
		n, err := s.out.take(chunkSize)
		if err != nil {
			c.fail(s, "canceled")
			return
		}
		k, rerr := f.Read(buf[:n])
		if k < n {
			s.out.add(int64(n - k))
		}
		if k > 0 {
			h.Write(buf[:k])
			if err := c.send(fOut, s.id, buf[:k]); err != nil {
				return
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			c.fail(s, rerr.Error())
			return
		}
	}
	_ = c.send(fExit, s.id, mustJSON(exitInfo{SHA256: hex.EncodeToString(h.Sum(nil)), Size: st.Size()}))
	c.remove(s.id)
}
