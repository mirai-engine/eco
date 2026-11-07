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
	"sync"
	"sync/atomic"
	"time"
)

const (
	ringCap        = 16 << 20 // output retained per stream of a job, for resuming after a disconnect
	maxJobsPerPeer = 256
	maxTimeout     = 24 * time.Hour
)

// openReq starts a stream. Method is one of exec, put, get, ping (pair is handled before the mux).
type openReq struct {
	Method string `json:"method"`
	Name   string `json:"name,omitempty"` // pair: label of the client

	// exec
	Job        string   `json:"job,omitempty"` // client-chosen idempotency key; makes the job survive disconnects
	Executable string   `json:"executable,omitempty"`
	Args       []string `json:"args,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Env        []string `json:"env,omitempty"` // extra KEY=VALUE entries
	TimeoutMS  int      `json:"timeout_ms,omitempty"`
	Stdin      bool     `json:"stdin,omitempty"`
	OutOffset  int64    `json:"out_offset,omitempty"` // bytes of stdout the client already has
	ErrOffset  int64    `json:"err_offset,omitempty"`

	// put / get
	Path   string `json:"path,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	Size   *int64 `json:"size,omitempty"`   // put: expected size
	Offset int64  `json:"offset,omitempty"` // get: resume position
}

type exitInfo struct {
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

type metaInfo struct {
	Started bool   `json:"started,omitempty"`
	Job     string `json:"job,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
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
}

type job struct {
	m       *muxServer
	key     string
	durable bool
	req     openReq
	ready   chan struct{}
	startEr error

	mu      sync.Mutex
	cond    *sync.Cond
	rings   [2]*ring // 0 stdout, 1 stderr
	sent    [2]int64
	att     *attachment
	done    bool
	exit    exitInfo
	end     time.Time
	killed  string
	started bool
	cmd     *exec.Cmd
	stdinW  io.WriteCloser
	grace   *time.Timer
	timeout *time.Timer
}

func newJob(m *muxServer, key string, req openReq) *job {
	j := &job{m: m, key: key, durable: req.Job != "", req: req, ready: make(chan struct{})}
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

func (j *job) run(stdout, stderr io.Reader) {
	var wg sync.WaitGroup
	for i, r := range []io.Reader{stdout, stderr} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, chunkSize)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					j.write(i, buf[:n])
				}
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	err := j.cmd.Wait()
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
func (j *job) attach(s *serverStream, off [2]int64) error {
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
	att := &attachment{s: s, next: off}
	j.att = att
	j.sent = off
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
		if !j.done && j.durable && j.grace == nil {
			j.grace = time.AfterFunc(j.m.detachGrace, func() { j.kill("no client reattached in time") })
		}
	}
	j.cond.Broadcast()
	j.mu.Unlock()
}

// pump streams ring contents and finally the exit status to the attached stream.
func (j *job) pump(att *attachment) {
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
	detachGrace time.Duration // kill a durable job nobody reattaches to
	retain      time.Duration // how long finished jobs stay available for reattaching
	stop        chan struct{}
}

func newMuxServer() *muxServer {
	m := &muxServer{jobs: map[string]*job{}, perPeer: map[string]int{}, detachGrace: 10 * time.Minute, retain: 10 * time.Minute, stop: make(chan struct{})}
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
	case "put":
		s.stdin = newFrameQueue()
		go c.putStream(s, req)
	case "get":
		go c.getStream(s, req)
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
	if err := j.attach(s, [2]int64{req.OutOffset, req.ErrOffset}); err != nil {
		if fresh && !j.durable {
			j.kill("canceled")
		}
		c.fail(s, err.Error())
		return
	}
	_ = c.send(fMeta, s.id, mustJSON(metaInfo{Started: true, Job: req.Job}))
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
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		j.startEr = err
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		j.startEr = err
		return
	}
	if req.Stdin {
		if j.stdinW, err = cmd.StdinPipe(); err != nil {
			j.startEr = err
			return
		}
	}
	if err := cmd.Start(); err != nil {
		j.startEr = err
		return
	}
	j.mu.Lock()
	j.cmd, j.started = cmd, true
	pending := j.killed
	if req.TimeoutMS > 0 {
		j.timeout = time.AfterFunc(time.Duration(req.TimeoutMS)*time.Millisecond, func() { j.kill("timeout") })
	}
	j.mu.Unlock()
	go j.run(stdout, stderr)
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
