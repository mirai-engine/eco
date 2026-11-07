package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

const maxLine = 1 << 20
const maxRequests = 4096
const maxOutput = 8 << 20

type request struct {
	ID         string   `json:"id"`
	Method     string   `json:"method"`
	Executable string   `json:"executable,omitempty"`
	Args       []string `json:"args,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	TimeoutMS  int      `json:"timeout_ms,omitempty"`
}
type event struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Data     []byte `json:"data,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
}
type writer struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *writer) send(e event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return json.NewEncoder(w.w).Encode(e)
}
func tlsConfig(certPath, keyPath, caPath string, server bool, name string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid CA certificate")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	if server {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	} else {
		cfg.RootCAs = pool
		cfg.ServerName = name
	}
	return cfg, nil
}
func serveConn(conn net.Conn) {
	defer conn.Close()
	output := &writer{w: conn}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), maxLine)
	seen := make(map[string]bool)
	for sc.Scan() {
		var q request
		if err := json.Unmarshal(sc.Bytes(), &q); err != nil {
			_ = output.send(event{Type: "error", Error: "invalid JSON"})
			continue
		}
		if q.ID == "" || len(q.ID) > 128 {
			_ = output.send(event{ID: q.ID, Type: "error", Error: "invalid id"})
			continue
		}
		if seen[q.ID] {
			_ = output.send(event{ID: q.ID, Type: "error", Error: "duplicate id"})
			continue
		}
		if len(seen) >= maxRequests {
			_ = output.send(event{ID: q.ID, Type: "error", Error: "request limit reached; reconnect"})
			return
		}
		seen[q.ID] = true
		switch q.Method {
		case "ping":
			_ = output.send(event{ID: q.ID, Type: "pong"})
		case "exec":
			run(q, output)
		default:
			_ = output.send(event{ID: q.ID, Type: "error", Error: "unknown method"})
		}
	}
}

type limitedWriter struct {
	out       *writer
	id, kind  string
	remaining *int
	mu        *sync.Mutex
	truncated *bool
}

func (w limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	take := n
	if take > *w.remaining {
		take = *w.remaining
		*w.truncated = true
	}
	if take > 0 {
		if err := w.out.send(event{ID: w.id, Type: w.kind, Data: p[:take]}); err != nil {
			return 0, err
		}
		*w.remaining -= take
	}
	return n, nil
}
func run(q request, out *writer) {
	if q.Executable == "" || q.TimeoutMS < 0 || q.TimeoutMS > 3600000 {
		_ = out.send(event{ID: q.ID, Type: "error", Error: "invalid executable or timeout_ms"})
		return
	}
	timeout := q.TimeoutMS
	if timeout == 0 {
		timeout = 60000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, q.Executable, q.Args...)
	cmd.Dir = q.Cwd
	remaining := maxOutput
	truncated := false
	var mu sync.Mutex
	cmd.Stdout = limitedWriter{out, q.ID, "stdout", &remaining, &mu, &truncated}
	cmd.Stderr = limitedWriter{out, q.ID, "stderr", &remaining, &mu, &truncated}
	if err := cmd.Start(); err != nil {
		_ = out.send(event{ID: q.ID, Type: "error", Error: err.Error()})
		return
	}
	_ = out.send(event{ID: q.ID, Type: "started"})
	err := cmd.Wait()
	code := cmd.ProcessState.ExitCode()
	e := event{ID: q.ID, Type: "exit", ExitCode: &code}
	if ctx.Err() != nil {
		e.Error = "timeout"
	} else if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			e.Error = err.Error()
		}
	}
	if truncated {
		if e.Error != "" {
			e.Error += "; "
		}
		e.Error += "output truncated"
	}
	_ = out.send(e)
}
func main() {
	if err := mainErr(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "eco:", err)
		os.Exit(1)
	}
}
func mainErr(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: eco setup|serve|connect")
	}
	if args[0] == "setup" {
		if len(args) != 2 {
			return errors.New("usage: eco setup DIRECTORY")
		}
		return setup(args[1])
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	addr := f.String("addr", "", "listen or connect address host:port")
	cert := f.String("cert", "", "certificate PEM")
	key := f.String("key", "", "private key PEM")
	ca := f.String("ca", "", "trusted CA PEM")
	name := f.String("server-name", "", "server certificate name (connect)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if *addr == "" || *cert == "" || *key == "" || *ca == "" {
		return errors.New("addr, cert, key and ca are required")
	}
	server := args[0] == "serve"
	if !server && args[0] != "connect" {
		return errors.New("unknown mode")
	}
	if !server && *name == "" {
		return errors.New("server-name is required")
	}
	cfg, err := tlsConfig(*cert, *key, *ca, server, *name)
	if err != nil {
		return err
	}
	if server {
		listener, err := tls.Listen("tcp", *addr, cfg)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Fprintln(os.Stderr, "eco listening on", listener.Addr())
		for {
			c, err := listener.Accept()
			if err != nil {
				return err
			}
			go serveConn(c)
		}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", *addr, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := io.Copy(os.Stdout, conn); done <- err }()
	_, err = io.Copy(conn, os.Stdin)
	if err != nil {
		return err
	}
	if err := conn.CloseWrite(); err != nil {
		return err
	}
	return <-done
}
