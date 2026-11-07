package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const usage = `usage: eco COMMAND [flags]

  pair     --addr HOST:PORT              trust a server (approve the code on the server)
  serve    --addr HOST:PORT [--pair]     run the server

  run      [flags] -- CMD...             run a command, stream its output, mirror its exit code
           --wait 50s                    stop waiting after 50s; the command keeps running (exit 254)
  start    [flags] -- CMD...             start a command in the background and print its job id
  attach   JOB [--wait D] [--all]        follow a job: output not seen yet, then its exit code
  jobs     [--json]                      list your jobs on the server
  kill     JOB                           stop a job and its process tree

  cat      REMOTE                        print a remote file
  write    REMOTE                        store stdin as a remote file (atomic)
  put      LOCAL REMOTE                  upload a file (verified, atomic)
  get      REMOTE LOCAL                  download a file (resumable, verified)
  forward  [LADDR:]LPORT:HOST:PORT       reach HOST:PORT as seen from the server (like ssh -L)

  connect                                JSON-lines session for programs (concurrent commands)
  ping                                   check the connection

Every command except serve and pair takes --addr HOST:PORT; it defaults to $ECO_ADDR, or to the
server if only one is paired.
run/start flags: --cwd DIR, --env K=V (repeatable), --timeout D, --job ID, --stdin (run only).`

// exitRunning is the exit status when eco stops waiting for a command that is still running.
const exitRunning = 254

// exitCode is returned by commands that mirror a remote exit status.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func main() {
	err := mainErr(os.Args[1:])
	var code exitCode
	switch {
	case err == nil:
	case errors.As(err, &code):
		os.Exit(int(code))
	default:
		fmt.Fprintln(os.Stderr, "eco:", err)
		os.Exit(255)
	}
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func mainErr(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	mode := args[0]
	f := flag.NewFlagSet(mode, flag.ContinueOnError)
	addr := f.String("addr", "", "server address host:port")
	dir := f.String("dir", "", "identity and trust directory (default $ECO_HOME or ~/.eco)")
	pairing := f.Bool("pair", false, "serve: let new clients pair, each approved interactively")
	label := f.String("name", "", "pair: label shown to the server operator (default hostname)")
	cwd := f.String("cwd", "", "run/start: working directory on the server")
	timeout := f.Duration("timeout", 0, "run/start: kill the command after this long (0 = no limit)")
	withStdin := f.Bool("stdin", false, "run: forward local stdin (the command then cannot survive a disconnect)")
	wait := f.Duration("wait", 0, "run/attach: stop waiting after this long and leave the command running")
	jobID := f.String("job", "", "run/start: job id (default: generated)")
	all := f.Bool("all", false, "attach: replay all retained output, not only what was not seen yet")
	asJSON := f.Bool("json", false, "jobs: print JSON")
	var env listFlag
	f.Var(&env, "env", "run/start: extra KEY=VALUE for the command (repeatable)")
	// For run/start everything from the first positional argument on is the command. Other commands also
	// accept flags after their arguments (eco attach JOB --wait 30s), up to a "--".
	var pos []string
	rest := args[1:]
	for {
		if err := f.Parse(rest); err != nil {
			return err
		}
		ended := len(rest)-f.NArg() > 0 && rest[len(rest)-f.NArg()-1] == "--"
		if f.NArg() == 0 || ended || mode == "run" || mode == "start" {
			pos = append(pos, f.Args()...)
			break
		}
		pos = append(pos, f.Arg(0))
		rest = f.Args()[1:]
	}
	switch mode {
	case "pair", "serve", "run", "start", "attach", "jobs", "kill", "cat", "write", "put", "get", "forward", "connect", "ping":
	default:
		return errors.New(usage)
	}
	state, err := stateDir(*dir)
	if err != nil {
		return err
	}
	if *addr == "" && mode != "pair" && mode != "serve" {
		if *addr, err = defaultAddr(state); err != nil {
			return err
		}
	}
	if *addr == "" {
		return errors.New("--addr is required")
	}
	client := &Client{Addr: *addr, Dir: state}
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	nargs := func(n int, shape string) error {
		if len(pos) != n {
			return fmt.Errorf("usage: eco %s %s", mode, shape)
		}
		return nil
	}
	// finish turns a job result into eco's own exit status.
	finish := func(res ExecResult, err error) error {
		if res.Running {
			fmt.Fprintf(os.Stderr, "eco: job %s is still running; follow it with: eco attach %s (or stop it: eco kill %s)\n", res.Job, res.Job, res.Job)
			return exitCode(exitRunning)
		}
		if err != nil {
			return err
		}
		if res.Error != "" {
			return fmt.Errorf("%s", res.Error)
		}
		if res.ExitCode != 0 {
			return exitCode(max(res.ExitCode, 1))
		}
		return nil
	}

	switch mode {
	case "pair":
		return pairWith(*addr, state, *label, os.Stderr)
	case "serve":
		return serve(*addr, state, *pairing)
	case "ping":
		start := time.Now()
		if err := client.Ping(ctx); err != nil {
			return err
		}
		fmt.Printf("pong from %s in %s\n", *addr, time.Since(start).Round(100*time.Microsecond))
		return nil
	case "run", "start":
		if len(pos) == 0 {
			return fmt.Errorf("%s: command required after --", mode)
		}
		o := ExecOpts{Executable: pos[0], Args: pos[1:], Cwd: *cwd, Env: env, Timeout: *timeout,
			Stdout: os.Stdout, Stderr: os.Stderr, Durable: true, Keep: true, JobID: *jobID, Wait: *wait}
		if mode == "start" {
			o.Wait, o.DetachOnStart, o.Stdout, o.Stderr = 0, true, nil, nil
			res, err := client.Exec(ctx, o)
			if err != nil {
				return err
			}
			if !res.Running { // finished before eco detached
				fmt.Println(res.Job)
				return finish(res, nil)
			}
			fmt.Println(res.Job)
			return nil
		}
		if *withStdin {
			if *wait > 0 {
				return errors.New("--stdin cannot be combined with --wait")
			}
			o.Stdin, o.Keep = os.Stdin, false
		}
		return finish(client.Exec(ctx, o))
	case "attach":
		if err := nargs(1, "JOB [--wait D] [--all]"); err != nil {
			return err
		}
		return finish(client.Attach(ctx, AttachOpts{Job: pos[0], All: *all, Wait: *wait, Stdout: os.Stdout, Stderr: os.Stderr}))
	case "jobs":
		list, err := client.Jobs()
		if err != nil {
			return err
		}
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(list)
		}
		printJobs(os.Stdout, list)
		return nil
	case "kill":
		if err := nargs(1, "JOB"); err != nil {
			return err
		}
		return client.Kill(pos[0])
	case "cat":
		if err := nargs(1, "REMOTE"); err != nil {
			return err
		}
		return client.Cat(ctx, pos[0], os.Stdout)
	case "write":
		if err := nargs(1, "REMOTE   (content on stdin)"); err != nil {
			return err
		}
		return client.Write(ctx, os.Stdin, pos[0])
	case "put":
		if err := nargs(2, "LOCAL REMOTE"); err != nil {
			return err
		}
		return client.Put(ctx, pos[0], pos[1])
	case "get":
		if err := nargs(2, "REMOTE LOCAL"); err != nil {
			return err
		}
		return client.Get(ctx, pos[0], pos[1])
	case "forward":
		if err := nargs(1, "[LADDR:]LPORT:HOST:PORT"); err != nil {
			return err
		}
		listen, target, err := parseForward(pos[0])
		if err != nil {
			return err
		}
		return client.Forward(ctx, listen, target, os.Stderr)
	default: // connect
		return connectJSON(ctx, client, os.Stdin, os.Stdout)
	}
}

// defaultAddr picks the server when --addr is omitted: $ECO_ADDR, else the only paired server.
func defaultAddr(state string) (string, error) {
	if a := os.Getenv("ECO_ADDR"); a != "" {
		return a, nil
	}
	rows, err := readLines(filepath.Join(state, "known_servers"))
	if err != nil {
		return "", err
	}
	switch len(rows) {
	case 0:
		return "", errors.New("no server paired yet: run `eco pair --addr HOST:PORT`")
	case 1:
		return rows[0][0], nil
	}
	return "", errors.New("several servers are paired: pass --addr HOST:PORT or set ECO_ADDR")
}

// parseForward reads [LADDR:]LPORT:HOST:PORT. The local side defaults to 127.0.0.1.
func parseForward(spec string) (listen, target string, err error) {
	p := strings.Split(spec, ":")
	switch len(p) {
	case 3:
		return net.JoinHostPort("127.0.0.1", p[0]), net.JoinHostPort(p[1], p[2]), nil
	case 4:
		return net.JoinHostPort(p[0], p[1]), net.JoinHostPort(p[2], p[3]), nil
	}
	return "", "", errors.New("forward: expected [LADDR:]LPORT:HOST:PORT, e.g. 8765:127.0.0.1:8765")
}

func printJobs(w io.Writer, list []jobInfo) {
	if len(list) == 0 {
		fmt.Fprintln(w, "no jobs")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "JOB\tSTATE\tAGE\tUNREAD\tCOMMAND")
	for _, j := range list {
		state := "running"
		switch {
		case j.Running && j.Attached:
			state = "running (attached)"
		case !j.Running && j.Error != "":
			state = j.Error
		case !j.Running:
			state = fmt.Sprintf("exit %d", j.ExitCode)
		}
		cmd := j.Command
		if len(cmd) > 90 {
			cmd = cmd[:87] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d B\t%s\n", j.ID, state, time.Since(j.Started).Round(time.Second), j.Unread, cmd)
	}
	tw.Flush()
}

func serve(addr, state string, pairing bool) error {
	id, err := loadOrCreateIdentity(state)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", addr, serverTLS(id))
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintln(os.Stderr, "eco listening on", listener.Addr())
	fmt.Fprintln(os.Stderr, "server fingerprint:", ownFingerprint(id))
	if pairing {
		fmt.Fprintln(os.Stderr, "pairing enabled: new clients need your approval here")
	}
	return (&pairServer{dir: state, fp: ownFingerprint(id), enabled: pairing, approve: promptApprove}).serve(listener)
}

// ---------- JSON-lines session for programs ----------

type jsonReq struct {
	ID         string   `json:"id"`
	Method     string   `json:"method"`
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	Cwd        string   `json:"cwd"`
	Env        []string `json:"env"`
	TimeoutMS  int      `json:"timeout_ms"`
	Stdin      bool     `json:"stdin"`
	Data       []byte   `json:"data"`
	EOF        bool     `json:"eof"`
}

type jsonEvent struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Data     []byte `json:"data,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
}

type eventWriter struct {
	emit func(jsonEvent)
	id   string
	kind string
}

func (w eventWriter) Write(p []byte) (int, error) {
	w.emit(jsonEvent{ID: w.id, Type: w.kind, Data: append([]byte(nil), p...)})
	return len(p), nil
}

// connectJSON serves a stream of JSON requests (one per line) and emits JSON events. Requests run
// concurrently over one multiplexed connection; commands without stdin survive network drops.
//
//	{"id":"1","method":"exec","executable":"git","args":["status"],"cwd":"C:\\work","timeout_ms":60000}
//	{"id":"1","method":"stdin","data":"<base64>","eof":true}   (only for exec requests with "stdin":true)
//	{"id":"1","method":"cancel"}
//	{"id":"2","method":"ping"}
//
// Events: started, stdout/stderr (base64 data), exit (exit_code, error), pong, error.
func connectJSON(ctx context.Context, c *Client, in io.Reader, out io.Writer) error {
	var wmu sync.Mutex
	enc := json.NewEncoder(out)
	emit := func(e jsonEvent) {
		wmu.Lock()
		_ = enc.Encode(e)
		wmu.Unlock()
	}
	type call struct {
		cancel context.CancelFunc
		stdin  *io.PipeWriter
	}
	var mu sync.Mutex
	calls := map[string]*call{}
	seen := map[string]bool{}
	nonce := randomID()
	var wg sync.WaitGroup

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		var q jsonReq
		if err := json.Unmarshal(sc.Bytes(), &q); err != nil {
			emit(jsonEvent{Type: "error", Error: "invalid JSON"})
			continue
		}
		if q.ID == "" || len(q.ID) > 128 {
			emit(jsonEvent{ID: q.ID, Type: "error", Error: "invalid id"})
			continue
		}
		switch q.Method {
		case "ping":
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := c.Ping(ctx); err != nil {
					emit(jsonEvent{ID: q.ID, Type: "error", Error: err.Error()})
					return
				}
				emit(jsonEvent{ID: q.ID, Type: "pong"})
			}()
		case "exec":
			mu.Lock()
			dup := seen[q.ID]
			seen[q.ID] = true
			mu.Unlock()
			if dup {
				emit(jsonEvent{ID: q.ID, Type: "error", Error: "duplicate id"})
				continue
			}
			if q.Executable == "" || q.TimeoutMS < 0 {
				emit(jsonEvent{ID: q.ID, Type: "error", Error: "invalid executable or timeout_ms"})
				continue
			}
			cctx, cancel := context.WithCancel(ctx)
			cl := &call{cancel: cancel}
			o := ExecOpts{Executable: q.Executable, Args: q.Args, Cwd: q.Cwd, Env: q.Env,
				Timeout: time.Duration(q.TimeoutMS) * time.Millisecond,
				Stdout:  eventWriter{emit, q.ID, "stdout"}, Stderr: eventWriter{emit, q.ID, "stderr"},
				Durable: true, JobID: nonce + "-" + q.ID,
				OnStart: func() { emit(jsonEvent{ID: q.ID, Type: "started"}) }}
			if q.Stdin {
				pr, pw := io.Pipe()
				o.Stdin, cl.stdin = pr, pw
			}
			mu.Lock()
			calls[q.ID] = cl
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer cancel()
				res, err := c.Exec(cctx, o)
				mu.Lock()
				delete(calls, q.ID)
				mu.Unlock()
				if err != nil && res == (ExecResult{Job: res.Job}) {
					emit(jsonEvent{ID: q.ID, Type: "error", Error: err.Error()})
					return
				}
				code := res.ExitCode
				emit(jsonEvent{ID: q.ID, Type: "exit", ExitCode: &code, Error: res.Error})
			}()
		case "stdin":
			mu.Lock()
			cl := calls[q.ID]
			mu.Unlock()
			if cl == nil || cl.stdin == nil {
				emit(jsonEvent{ID: q.ID, Type: "error", Error: "no running command with stdin for this id"})
				continue
			}
			if len(q.Data) > 0 {
				if _, err := cl.stdin.Write(q.Data); err != nil {
					emit(jsonEvent{ID: q.ID, Type: "error", Error: err.Error()})
					continue
				}
			}
			if q.EOF {
				cl.stdin.Close()
			}
		case "cancel":
			mu.Lock()
			cl := calls[q.ID]
			mu.Unlock()
			if cl == nil {
				emit(jsonEvent{ID: q.ID, Type: "error", Error: "no running command with this id"})
				continue
			}
			cl.cancel()
		default:
			emit(jsonEvent{ID: q.ID, Type: "error", Error: "unknown method"})
		}
	}
	wg.Wait()
	return sc.Err()
}
