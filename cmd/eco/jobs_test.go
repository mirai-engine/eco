package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func tickerLines(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "line %03d\n", i)
	}
	return b.String()
}

// A command that leaves a background process holding its stdout (Start-Process, `cmd &`) must finish
// when the command itself exits, not when the background process does.
func TestExitDoesNotWaitForBackgroundChildren(t *testing.T) {
	e := newEnv(t, nil)
	start := time.Now()
	so, _, res, err := e.exec("spawn", "30000")
	elapsed := time.Since(start)
	var pid int
	fmt.Sscanf(so, "child %d", &pid)
	if pid > 0 {
		t.Cleanup(func() {
			if p, err := os.FindProcess(pid); err == nil {
				p.Kill()
			}
		})
	}
	if err != nil || res.ExitCode != 0 || !strings.Contains(so, "parent done") {
		t.Fatalf("stdout=%q res=%+v err=%v", so, res, err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("waited %s for a background child", elapsed)
	}
}

// run --wait: stop waiting, the job keeps running, attach continues exactly where the output stopped.
func TestWaitDetachesAndAttachContinues(t *testing.T) {
	e := newEnv(t, func(m *muxServer) { m.detachGrace = 100 * time.Millisecond })
	exe, a := helper("ticker", "20", "100")
	var first bytes.Buffer
	res, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Stdout: &first,
		Durable: true, Keep: true, Wait: 600 * time.Millisecond})
	if err != nil || !res.Running || res.Job == "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if first.Len() == 0 || first.String() == tickerLines(20) {
		t.Fatalf("expected partial output, got %q", first.String())
	}
	time.Sleep(300 * time.Millisecond) // longer than detachGrace: Keep jobs are not killed
	var rest bytes.Buffer
	res2, err := e.cl.Attach(context.Background(), AttachOpts{Job: res.Job, Stdout: &rest})
	if err != nil || res2.Running || res2.ExitCode != 0 || res2.Error != "" {
		t.Fatalf("attach res=%+v err=%v", res2, err)
	}
	if got := first.String() + rest.String(); got != tickerLines(20) {
		t.Fatalf("output lost or duplicated:\n%q", got)
	}
	// Nothing left to read: a second attach returns the exit status with no output.
	var again bytes.Buffer
	res3, err := e.cl.Attach(context.Background(), AttachOpts{Job: res.Job, Stdout: &again})
	if err != nil || again.Len() != 0 || res3.ExitCode != 0 {
		t.Fatalf("second attach: %q %+v %v", again.String(), res3, err)
	}
	var all bytes.Buffer
	if _, err := e.cl.Attach(context.Background(), AttachOpts{Job: res.Job, All: true, Stdout: &all}); err != nil || all.String() != tickerLines(20) {
		t.Fatalf("attach --all: %q %v", all.String(), err)
	}
}

// Attach --wait also returns while the job is still running, and Ctrl-C on attach detaches only.
func TestAttachWaitAndCancelDetach(t *testing.T) {
	e := newEnv(t, nil)
	exe, a := helper("ticker", "30", "100")
	res, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Durable: true, Keep: true, DetachOnStart: true})
	if err != nil || !res.Running {
		t.Fatalf("start: %+v %v", res, err)
	}
	var out bytes.Buffer
	r, err := e.cl.Attach(context.Background(), AttachOpts{Job: res.Job, Wait: 400 * time.Millisecond, Stdout: &out})
	if err != nil || !r.Running {
		t.Fatalf("attach --wait: %+v %v", r, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	r, err = e.cl.Attach(ctx, AttachOpts{Job: res.Job, Stdout: &out})
	if err != nil || !r.Running {
		t.Fatalf("cancelled attach should detach: %+v %v", r, err)
	}
	r, err = e.cl.Attach(context.Background(), AttachOpts{Job: res.Job, Stdout: &out})
	if err != nil || r.ExitCode != 0 || out.String() != tickerLines(30) {
		t.Fatalf("final attach: %+v %v\n%q", r, err, out.String())
	}
}

// A client that dies without detaching (killed by an agent's tool timeout) loses nothing: the Keep job
// runs to the end and a new client replays the output that was never confirmed.
func TestKeepJobSurvivesClientDeath(t *testing.T) {
	e := newEnv(t, func(m *muxServer) { m.detachGrace = 100 * time.Millisecond })
	exe, a := helper("ticker", "10", "50")
	s, err := e.cl.open(openReq{Method: "exec", Job: "agent-1", Executable: exe, Args: a, Env: helperEnv(), Keep: true})
	if err != nil {
		t.Fatal(err)
	}
	if f, err := s.recv(); err != nil || f.typ != fMeta {
		t.Fatalf("%v %v", f.typ, err)
	}
	e.cl.Close() // abrupt: no detach
	time.Sleep(900 * time.Millisecond)
	cl := &Client{Addr: e.addr, Dir: e.cdir}
	defer cl.Close()
	list, err := cl.Jobs()
	if err != nil || len(list) != 1 || list[0].ID != "agent-1" || list[0].Running || list[0].ExitCode != 0 {
		t.Fatalf("jobs: %+v %v", list, err)
	}
	var out bytes.Buffer
	r, err := cl.Attach(context.Background(), AttachOpts{Job: "agent-1", Stdout: &out})
	if err != nil || r.ExitCode != 0 || out.String() != tickerLines(10) {
		t.Fatalf("%+v %v %q", r, err, out.String())
	}
}

func TestStartJobsKill(t *testing.T) {
	e := newEnv(t, nil)
	exe, a := helper("sleep", "30000")
	res, err := e.cl.Exec(context.Background(), ExecOpts{Executable: exe, Args: a, Env: helperEnv(), Durable: true, Keep: true, DetachOnStart: true, JobID: "build"})
	if err != nil || !res.Running || res.Job != "build" {
		t.Fatalf("%+v %v", res, err)
	}
	list, err := e.cl.Jobs()
	if err != nil || len(list) != 1 || !list[0].Running || !strings.Contains(list[0].Command, "sleep") {
		t.Fatalf("%+v %v", list, err)
	}
	if err := e.cl.Kill("build"); err != nil {
		t.Fatal(err)
	}
	r, err := e.cl.Attach(context.Background(), AttachOpts{Job: "build"})
	if err != nil || r.Error != "killed" {
		t.Fatalf("%+v %v", r, err)
	}
	if err := e.cl.Kill("nope"); err == nil {
		t.Fatal("killing an unknown job should fail")
	}
	if _, err := e.cl.Attach(context.Background(), AttachOpts{Job: "nope"}); err == nil || !strings.Contains(err.Error(), "no such job") {
		t.Fatalf("attach unknown: %v", err)
	}
}

func TestWriteAndCat(t *testing.T) {
	e := newEnv(t, nil)
	remote := filepath.Join(t.TempDir(), "sub", "file.odin")
	content := "package x\n\n// quotes \" ' ` $HOME %PATH% and ñ survive untouched\n"
	if err := e.cl.Write(context.Background(), strings.NewReader(content), remote); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := e.cl.Cat(context.Background(), remote, &got); err != nil || got.String() != content {
		t.Fatalf("%q %v", got.String(), err)
	}
	if err := e.cl.Cat(context.Background(), remote+".missing", io.Discard); err == nil {
		t.Fatal("cat of a missing file should fail")
	}
}

func TestForward(t *testing.T) {
	e := newEnv(t, nil)
	target, err := net.Listen("tcp", "127.0.0.1:0") // a service only reachable on the server's loopback
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c)
				c.Write(append([]byte("echo:"), b...))
			}()
		}
	}()
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	local := probe.Addr().String()
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.cl.Forward(ctx, local, target.Addr().String(), io.Discard) }()
	var c net.Conn
	for i := 0; i < 50; i++ {
		if c, err = net.Dial("tcp", local); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("0123456789"), 300000) // 3 MB, crosses several flow-control windows
	go func() {
		c.Write(big)
		c.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(c)
	c.Close()
	if err != nil || !bytes.Equal(got, append([]byte("echo:"), big...)) {
		t.Fatalf("got %d bytes, err %v", len(got), err)
	}
	// Several connections at once.
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			c, err := net.Dial("tcp", local)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			msg := "conn " + strconv.Itoa(i)
			c.Write([]byte(msg))
			c.(*net.TCPConn).CloseWrite()
			b, _ := io.ReadAll(c)
			if string(b) != "echo:"+msg {
				errs <- fmt.Errorf("got %q", b)
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < 5; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestParseForwardAndDefaultAddr(t *testing.T) {
	l, tg, err := parseForward("8765:127.0.0.1:9000")
	if err != nil || l != "127.0.0.1:8765" || tg != "127.0.0.1:9000" {
		t.Fatal(l, tg, err)
	}
	l, tg, err = parseForward("0.0.0.0:80:localhost:8080")
	if err != nil || l != "0.0.0.0:80" || tg != "localhost:8080" {
		t.Fatal(l, tg, err)
	}
	if _, _, err := parseForward("8080"); err == nil {
		t.Fatal("expected error")
	}
	dir := t.TempDir()
	t.Setenv("ECO_ADDR", "")
	if _, err := defaultAddr(dir); err == nil {
		t.Fatal("no server paired: expected error")
	}
	saveKnownServer(dir, "10.0.0.1:8443", "aa")
	if a, err := defaultAddr(dir); err != nil || a != "10.0.0.1:8443" {
		t.Fatal(a, err)
	}
	saveKnownServer(dir, "10.0.0.2:8443", "bb")
	if _, err := defaultAddr(dir); err == nil {
		t.Fatal("two servers: expected error")
	}
	t.Setenv("ECO_ADDR", "10.0.0.2:8443")
	if a, _ := defaultAddr(dir); a != "10.0.0.2:8443" {
		t.Fatal(a)
	}
}

func TestCLIFlagsAfterArguments(t *testing.T) {
	e := newEnv(t, nil)
	t.Setenv("ECO_ADDR", e.addr)
	exe, a := helper("ticker", "3", "10")
	// run: everything after the first argument is the command, even things that look like flags.
	args := append([]string{"run", "--dir", e.cdir, "--job", "cli1", "--env", "ECO_HELPER=1", "--", exe}, a...)
	if err := mainErr(args); err != nil {
		t.Fatal(err)
	}
	if err := mainErr([]string{"attach", "cli1", "--dir", e.cdir, "--wait", "5s"}); err != nil {
		t.Fatal(err)
	}
	err := mainErr([]string{"attach", "missing", "--dir", e.cdir})
	if err == nil || !strings.Contains(err.Error(), "no such job") {
		t.Fatal(err)
	}
}
