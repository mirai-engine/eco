package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- helper process: the test binary itself acts as the remote program ----------

func helper(mode string, args ...string) (string, []string) {
	return os.Args[0], append([]string{"-test.run=TestHelperProcess", "--", mode}, args...)
}

func helperEnv() []string { return []string{"ECO_HELPER=1"} }

func TestHelperProcess(t *testing.T) {
	if os.Getenv("ECO_HELPER") != "1" {
		return
	}
	a := os.Args
	for i, s := range a {
		if s == "--" {
			a = a[i+1:]
			break
		}
	}
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	switch a[0] {
	case "out": // out N: N bytes of a position-dependent pattern
		n := atoi(a[1])
		buf := make([]byte, 64*1024)
		for pos := 0; pos < n; {
			k := min(len(buf), n-pos)
			for i := 0; i < k; i++ {
				buf[i] = byte((pos + i) % 251)
			}
			os.Stdout.Write(buf[:k])
			pos += k
		}
	case "err":
		fmt.Fprint(os.Stderr, "to-stderr")
		fmt.Print("to-stdout")
		os.Exit(3)
	case "sleep": // sleep MS
		time.Sleep(time.Duration(atoi(a[1])) * time.Millisecond)
	case "echo":
		io.Copy(os.Stdout, os.Stdin)
	case "env":
		fmt.Print(os.Getenv(a[1]))
	case "pwd":
		d, _ := os.Getwd()
		fmt.Print(d)
	case "ticker": // ticker COUNT MS [MARKERFILE]: one line per tick; marker file gets one line per launch
		if len(a) > 3 {
			f, _ := os.OpenFile(a[3], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString("launched\n")
			f.Close()
		}
		for i := 0; i < atoi(a[1]); i++ {
			fmt.Printf("line %03d\n", i)
			time.Sleep(time.Duration(atoi(a[2])) * time.Millisecond)
		}
	case "spawn": // spawn MS: start a child that inherits stdout/stderr and sleeps MS, print its pid, exit
		exe, args := helper("sleep", a[1])
		c := exec.Command(exe, args...)
		c.Env = append(os.Environ(), helperEnv()...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Start(); err != nil {
			fmt.Print("spawn failed: ", err)
			os.Exit(1)
		}
		fmt.Printf("child %d\nparent done\n", c.Process.Pid)
	case "append": // append FILE MS: keeps writing to FILE until killed
		for {
			f, _ := os.OpenFile(a[1], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString("x\n")
			f.Close()
			time.Sleep(time.Duration(atoi(a[2])) * time.Millisecond)
		}
	}
	os.Exit(0)
}

type patternChecker struct {
	pos int64
	bad bool
	// pause, when set, delays every write to simulate a slow consumer.
	pause func()
}

func (p *patternChecker) Write(b []byte) (int, error) {
	for _, c := range b {
		if c != byte(p.pos%251) {
			p.bad = true
		}
		p.pos++
	}
	if p.pause != nil {
		p.pause()
	}
	return len(b), nil
}

// ---------- environment ----------

type env struct {
	t      *testing.T
	addr   string
	cdir   string
	sdir   string
	mux    *muxServer
	cl     *Client
	closed chan struct{}
}

// newEnv starts a server (pairing disabled) with one already authorized client.
func newEnv(t *testing.T, tune func(*muxServer)) *env {
	t.Helper()
	sdir, cdir := t.TempDir(), t.TempDir()
	sid, err := loadOrCreateIdentity(sdir)
	if err != nil {
		t.Fatal(err)
	}
	cid, err := loadOrCreateIdentity(cdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorize(sdir, ownFingerprint(cid), "test"); err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS(sid))
	if err != nil {
		t.Fatal(err)
	}
	mux := newMuxServer()
	if tune != nil {
		tune(mux)
	}
	ps := &pairServer{dir: sdir, fp: ownFingerprint(sid), mux: mux, approve: no}
	go ps.serve(l)
	addr := l.Addr().String()
	if err := saveKnownServer(cdir, addr, ownFingerprint(sid)); err != nil {
		t.Fatal(err)
	}
	cl := &Client{Addr: addr, Dir: cdir, ReconnectFor: 20 * time.Second}
	t.Cleanup(func() { cl.Close(); l.Close(); mux.close() })
	return &env{t: t, addr: addr, cdir: cdir, sdir: sdir, mux: mux, cl: cl}
}

func (e *env) dropConnection() {
	e.cl.mu.Lock()
	cc := e.cl.cc
	e.cl.mu.Unlock()
	if cc != nil {
		cc.conn.Close()
	}
}

func (e *env) exec(mode string, args ...string) (stdout, stderr string, res ExecResult, err error) {
	exe, a := helper(mode, args...)
	var so, se bytes.Buffer
	res, err = e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Stdout: &so, Stderr: &se})
	return so.String(), se.String(), res, err
}

// ---------- tests ----------

func TestExecSeparatesStreamsAndExitCode(t *testing.T) {
	e := newEnv(t, nil)
	so, se, res, err := e.exec("err")
	if err != nil {
		t.Fatal(err)
	}
	if so != "to-stdout" || se != "to-stderr" || res.ExitCode != 3 || res.Error != "" {
		t.Fatalf("stdout=%q stderr=%q res=%+v", so, se, res)
	}
}

func TestExecEnvAndCwd(t *testing.T) {
	e := newEnv(t, nil)
	exe, a := helper("env", "ECO_X")
	var so bytes.Buffer
	_, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: append(helperEnv(), "ECO_X=hello"), Stdout: &so})
	if err != nil || so.String() != "hello" {
		t.Fatalf("%q %v", so.String(), err)
	}
	dir := t.TempDir()
	exe, a = helper("pwd")
	so.Reset()
	_, err = e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Cwd: dir, Stdout: &so})
	want, _ := filepath.EvalSymlinks(dir)
	got, _ := filepath.EvalSymlinks(so.String())
	if err != nil || got != want {
		t.Fatalf("cwd %q want %q (%v)", got, want, err)
	}
}

func TestStartFailureIsReported(t *testing.T) {
	e := newEnv(t, nil)
	_, err := e.cl.Exec(context.Background(), ExecOpts{Executable: "definitely-not-a-real-program-eco"})
	if err == nil {
		t.Fatal("expected an error")
	}
}

// Eight 400 ms commands over one connection must overlap (the old protocol ran them one by one: 3.2 s).
func TestConcurrentCommandsShareOneConnection(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.cl.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.cl.mu.Lock()
	first := e.cl.cc
	e.cl.mu.Unlock()
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, _, err := e.exec("sleep", "400"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("commands did not run concurrently: %v", d)
	}
	e.cl.mu.Lock()
	same := e.cl.cc == first
	e.cl.mu.Unlock()
	if !same {
		t.Fatal("a second connection was opened")
	}
}

// 40 MiB exceeds both the old 8 MiB cap and the retained ring (16 MiB): flow control must deliver every
// byte, in order, even though the consumer is slow.
func TestLargeOutputWithSlowConsumer(t *testing.T) {
	e := newEnv(t, nil)
	const n = 40 << 20
	exe, a := helper("out", strconv.Itoa(n))
	pc := &patternChecker{}
	var writes int
	pc.pause = func() {
		if writes++; writes%32 == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	res, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Stdout: pc})
	if err != nil || res.Error != "" {
		t.Fatalf("%v %+v", err, res)
	}
	if pc.pos != n || pc.bad {
		t.Fatalf("received %d bytes (want %d), corrupted=%v", pc.pos, n, pc.bad)
	}
}

// One stalled consumer must not block other streams of the same connection.
func TestStalledStreamDoesNotBlockOthers(t *testing.T) {
	e := newEnv(t, nil)
	exe, a := helper("out", strconv.Itoa(64<<20))
	release := make(chan struct{})
	stalled := &patternChecker{pause: func() { <-release }}
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Stdout: stalled})
	}()
	time.Sleep(300 * time.Millisecond) // let the stalled stream fill its window
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := e.cl.Ping(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := e.exec("env", "ECO_HELPER"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("other streams were delayed by the stalled one: %v", d)
	}
	close(release)
	<-done
}

func TestCancelKillsTheRemoteCommand(t *testing.T) {
	e := newEnv(t, nil)
	exe, a := helper("sleep", "60000")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	start := time.Now()
	res, err := e.cl.Exec(ctx, ExecOpts{Executable: exe, Args: a, Env: helperEnv()})
	if res.Error != "canceled" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancel took too long")
	}
}

func TestTimeout(t *testing.T) {
	e := newEnv(t, nil)
	exe, a := helper("sleep", "60000")
	res, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Timeout: 400 * time.Millisecond})
	if err != nil || res.Error != "timeout" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestStdinStreaming(t *testing.T) {
	e := newEnv(t, nil)
	in := make([]byte, 6<<20) // larger than the stdin window: exercises credit in the other direction
	rand.Read(in)
	exe, a := helper("echo")
	var out bytes.Buffer
	res, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Stdin: bytes.NewReader(in), Stdout: &out})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	if !bytes.Equal(in, out.Bytes()) {
		t.Fatalf("echo mismatch: sent %d bytes, got %d", len(in), out.Len())
	}
}

// A durable job survives a dropped connection: the client reconnects, resumes from its offsets, receives
// every line exactly once, and the command is launched only once.
func TestReconnectResumesWithoutDuplicatesOrRerun(t *testing.T) {
	e := newEnv(t, nil)
	marker := filepath.Join(t.TempDir(), "launches")
	exe, a := helper("ticker", "30", "50", marker)
	var out bytes.Buffer
	done := make(chan struct{})
	var res ExecResult
	var err error
	go func() {
		defer close(done)
		res, err = e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Stdout: &out, Durable: true})
	}()
	time.Sleep(500 * time.Millisecond)
	e.dropConnection()
	time.Sleep(200 * time.Millisecond)
	e.dropConnection() // a second drop, possibly during the reattach
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out")
	}
	if err != nil || res.ExitCode != 0 || res.Error != "" {
		t.Fatalf("%v %+v", err, res)
	}
	var want strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&want, "line %03d\n", i)
	}
	if out.String() != want.String() {
		t.Fatalf("output after reconnect differs:\n%q", out.String())
	}
	if b, _ := os.ReadFile(marker); string(b) != "launched\n" {
		t.Fatalf("command launched %d times", strings.Count(string(b), "launched"))
	}
}

func TestDurableJobIsIdempotent(t *testing.T) {
	e := newEnv(t, nil)
	marker := filepath.Join(t.TempDir(), "launches")
	exe, a := helper("ticker", "3", "10", marker)
	run := func() string {
		var out bytes.Buffer
		if _, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Stdout: &out, Durable: true, JobID: "same-key"}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	first, second := run(), run()
	if first != second || first == "" {
		t.Fatalf("replay differs: %q vs %q", first, second)
	}
	if b, _ := os.ReadFile(marker); string(b) != "launched\n" {
		t.Fatalf("job ran %d times", strings.Count(string(b), "launched"))
	}
	// the same key for a different command is refused
	other, oa := helper("env", "ECO_HELPER")
	if _, err := e.cl.Exec(context.Background(), ExecOpts{Executable: other, Args: oa, Env: helperEnv(), Durable: true, JobID: "same-key"}); err == nil || !strings.Contains(err.Error(), "different command") {
		t.Fatalf("expected refusal, got %v", err)
	}
}

func TestEphemeralJobIsKilledWhenConnectionDrops(t *testing.T) {
	e := newEnv(t, nil)
	file := filepath.Join(t.TempDir(), "grow")
	exe, a := helper("append", file, "30")
	go e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv()})
	time.Sleep(600 * time.Millisecond)
	e.dropConnection()
	time.Sleep(800 * time.Millisecond)
	st1, _ := os.Stat(file)
	time.Sleep(400 * time.Millisecond)
	st2, _ := os.Stat(file)
	if st1 == nil || st1.Size() != st2.Size() {
		t.Fatal("the remote command kept running after its connection dropped")
	}
}

func TestDetachedDurableJobIsKilledAfterGrace(t *testing.T) {
	e := newEnv(t, func(m *muxServer) { m.detachGrace = 300 * time.Millisecond })
	file := filepath.Join(t.TempDir(), "grow")
	exe, a := helper("append", file, "30")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.cl.ReconnectFor = 50 * time.Millisecond // do not reattach
	go e.cl.Exec(ctx, ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Durable: true})
	time.Sleep(500 * time.Millisecond)
	// make reconnecting impossible so that nobody reattaches
	e.cl.mu.Lock()
	e.cl.Dir = t.TempDir()
	e.cl.mu.Unlock()
	e.dropConnection()
	time.Sleep(1500 * time.Millisecond)
	st1, _ := os.Stat(file)
	time.Sleep(400 * time.Millisecond)
	st2, _ := os.Stat(file)
	if st1 == nil || st1.Size() != st2.Size() {
		t.Fatal("a durable job nobody reattached to kept running past the grace period")
	}
}

func TestPutAndGetVerifyAndResume(t *testing.T) {
	e := newEnv(t, nil)
	tmp := t.TempDir()
	data := make([]byte, 5<<20+123)
	rand.Read(data)
	src := filepath.Join(tmp, "src.bin")
	os.WriteFile(src, data, 0644)
	sum := sha256.Sum256(data)

	remote := filepath.Join(tmp, "nested", "dir", "remote.bin")
	if err := e.cl.Put(context.Background(), src, remote); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(remote)
	if !bytes.Equal(got, data) {
		t.Fatal("uploaded file differs")
	}
	if _, err := os.Stat(remote + ".eco-part"); err == nil {
		t.Fatal("temporary upload file left behind")
	}

	local := filepath.Join(tmp, "got.bin")
	if err := e.cl.Get(context.Background(), remote, local); err != nil {
		t.Fatal(err)
	}
	if h, _ := fileSHA256(local); h != hex.EncodeToString(sum[:]) {
		t.Fatal("downloaded file differs")
	}

	// resume from a correct partial download
	local2 := filepath.Join(tmp, "resumed.bin")
	os.WriteFile(local2+".eco-part", data[:2<<20], 0644)
	if err := e.cl.Get(context.Background(), remote, local2); err != nil {
		t.Fatal(err)
	}
	if h, _ := fileSHA256(local2); h != hex.EncodeToString(sum[:]) {
		t.Fatal("resumed download differs")
	}

	// a corrupt partial is detected and discarded, never promoted to the final name
	local3 := filepath.Join(tmp, "corrupt.bin")
	bad := append([]byte(nil), data[:1<<20]...)
	bad[10] ^= 0xff
	os.WriteFile(local3+".eco-part", bad, 0644)
	if err := e.cl.Get(context.Background(), remote, local3); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected checksum error, got %v", err)
	}
	if _, err := os.Stat(local3); err == nil {
		t.Fatal("corrupt download was published")
	}
	if _, err := os.Stat(local3 + ".eco-part"); err == nil {
		t.Fatal("corrupt partial was kept for resuming")
	}
}

func TestPutRejectsCorruptedUpload(t *testing.T) {
	e := newEnv(t, nil)
	target := filepath.Join(t.TempDir(), "target.bin")
	cc, err := e.cl.conn()
	if err != nil {
		t.Fatal(err)
	}
	size := int64(10)
	s, err := cc.open(openReq{Method: "put", Path: target, Size: &size})
	if err != nil {
		t.Fatal(err)
	}
	defer s.release()
	if err := s.sendData([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	_ = cc.send(fStdinEOF, s.id, mustJSON(map[string]string{"sha256": strings.Repeat("ab", 32)}))
	f, err := s.recv()
	if err != nil || f.typ != fError || !strings.Contains(string(f.payload), "checksum") {
		t.Fatalf("got %+v %v", f, err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("corrupted upload was published")
	}
	if _, err := os.Stat(target + ".eco-part"); err == nil {
		t.Fatal("temporary file left behind")
	}
}

func TestGetMissingFile(t *testing.T) {
	e := newEnv(t, nil)
	err := e.cl.Get(context.Background(), filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "x"))
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestRingKeepsRecentOutputAndRejectsExpiredOffsets(t *testing.T) {
	r := &ring{cap: 1 << 20}
	var all []byte
	for i := 0; i < 50; i++ {
		b := bytes.Repeat([]byte{byte(i)}, 70000)
		all = append(all, b...)
		r.append(b)
	}
	if r.end != int64(len(all)) || r.end-r.start > r.cap+chunkSize {
		t.Fatalf("start=%d end=%d", r.start, r.end)
	}
	if r.start == 0 {
		t.Fatal("nothing was dropped")
	}
	got := r.read(r.start+5, 100)
	if !bytes.Equal(got, all[r.start+5:r.start+105]) {
		t.Fatal("read returned wrong bytes")
	}
	if r.read(r.start-1, 10) != nil || r.read(r.end, 10) != nil {
		t.Fatal("out-of-range read returned data")
	}

	m := newMuxServer()
	defer m.close()
	j := newJob(m, "k", openReq{Job: "j"})
	for i := 0; i < 40; i++ { // nobody attached: output beyond the cap is dropped, never blocks
		j.write(0, make([]byte, 1<<20))
	}
	if err := j.attach(&serverStream{}, [2]int64{0, 0}, metaInfo{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestFrameCodecRejectsOversizeFrames(t *testing.T) {
	var b bytes.Buffer
	if err := writeFrame(&b, fOut, 7, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	f, err := readFrame(&b)
	if err != nil || f.typ != fOut || f.stream != 7 || string(f.payload) != "hello" {
		t.Fatalf("%+v %v", f, err)
	}
	if err := writeFrame(io.Discard, fOut, 1, make([]byte, maxFrame+1)); err == nil {
		t.Fatal("oversize frame written")
	}
	hdr := []byte{fOut, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}
	if _, err := readFrame(bytes.NewReader(hdr)); err == nil {
		t.Fatal("oversize frame accepted")
	}
}

func TestConnectJSONRunsRequestsConcurrently(t *testing.T) {
	e := newEnv(t, nil)
	sleepExe, sleepArgs := helper("sleep", "500")
	echoExe, echoArgs := helper("echo")
	req := func(id, exe string, args []string, stdin bool) string {
		return string(mustJSON(jsonReq{ID: id, Method: "exec", Executable: exe, Args: args, Env: helperEnv(), Stdin: stdin})) + "\n"
	}
	input := req("a", sleepExe, sleepArgs, false) + req("b", sleepExe, sleepArgs, false) + req("c", echoExe, echoArgs, true) +
		string(mustJSON(jsonReq{ID: "p", Method: "ping"})) + "\n" +
		string(mustJSON(jsonReq{ID: "c", Method: "stdin", Data: []byte("hi there"), EOF: true})) + "\n" +
		string(mustJSON(jsonReq{ID: "a", Method: "exec", Executable: "x"})) + "\n" // duplicate id
	var out syncBuffer
	start := time.Now()
	if err := connectJSON(context.Background(), e.cl, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("requests ran serially: %v", d)
	}
	text := out.String()
	for _, want := range []string{`"id":"p","type":"pong"`, `"id":"a","type":"exit","exit_code":0`, `"id":"b","type":"exit","exit_code":0`,
		`"id":"c","type":"stdout","data":"aGkgdGhlcmU="`, `"id":"c","type":"exit","exit_code":0`, `duplicate id`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in:\n%s", want, text)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
