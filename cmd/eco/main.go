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
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

const usage = `usage: eco COMMAND [flags]

  pair     --addr HOST:PORT                    trust a server (approve the code on the server)
  serve    --addr HOST:PORT [--pair]           run the server
  run      --addr HOST:PORT [flags] -- CMD...  run a command, stream its output, mirror its exit code
  put      --addr HOST:PORT LOCAL REMOTE       upload a file (verified, atomic)
  get      --addr HOST:PORT REMOTE LOCAL       download a file (resumable, verified)
  connect  --addr HOST:PORT                    JSON-lines session for programs (concurrent commands)
  ping     --addr HOST:PORT                    check the connection`

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
	cwd := f.String("cwd", "", "run: working directory on the server")
	timeout := f.Duration("timeout", 0, "run: kill the command after this long (0 = no limit)")
	withStdin := f.Bool("stdin", false, "run: forward local stdin (the command then cannot survive a disconnect)")
	var env listFlag
	f.Var(&env, "env", "run: extra KEY=VALUE for the command (repeatable)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	switch mode {
	case "pair", "serve", "run", "put", "get", "connect", "ping":
	default:
		return errors.New(usage)
	}
	if *addr == "" {
		return errors.New("--addr is required")
	}
	state, err := stateDir(*dir)
	if err != nil {
		return err
	}
	client := &Client{Addr: *addr, Dir: state}
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

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
	case "run":
		if f.NArg() == 0 {
			return errors.New("run: command required after --")
		}
		o := ExecOpts{Executable: f.Arg(0), Args: f.Args()[1:], Cwd: *cwd, Env: env, Timeout: *timeout,
			Stdout: os.Stdout, Stderr: os.Stderr, Durable: true}
		if *withStdin {
			o.Stdin = os.Stdin
		}
		res, err := client.Exec(ctx, o)
		if err != nil && res == (ExecResult{}) {
			return err
		}
		if res.Error != "" {
			return fmt.Errorf("%s", res.Error)
		}
		if res.ExitCode != 0 {
			return exitCode(max(res.ExitCode, 1))
		}
		return nil
	case "put":
		if f.NArg() != 2 {
			return errors.New("usage: eco put --addr HOST:PORT LOCAL REMOTE")
		}
		return client.Put(ctx, f.Arg(0), f.Arg(1))
	case "get":
		if f.NArg() != 2 {
			return errors.New("usage: eco get --addr HOST:PORT REMOTE LOCAL")
		}
		return client.Get(ctx, f.Arg(0), f.Arg(1))
	default: // connect
		return connectJSON(ctx, client, os.Stdin, os.Stdout)
	}
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
				if err != nil && res == (ExecResult{}) {
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
