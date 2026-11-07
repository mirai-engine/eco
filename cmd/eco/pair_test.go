package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startPairServer runs a pairing server on a loopback port and returns its address and requests channel.
func startPairServer(t *testing.T, enabled bool, answer func(pairRequest) bool) (addr, dir string, requests chan pairRequest, id tls.Certificate) {
	t.Helper()
	dir = t.TempDir()
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS(id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	requests = make(chan pairRequest, 16)
	ps := &pairServer{dir: dir, fp: ownFingerprint(id), enabled: enabled, approve: func(r pairRequest) bool {
		requests <- r
		return answer(r)
	}}
	t.Cleanup(func() {
		if ps.mux != nil {
			ps.mux.close()
		}
	})
	go ps.serve(l)
	return l.Addr().String(), dir, requests, id
}

func yes(pairRequest) bool { return true }
func no(pairRequest) bool  { return false }

func codeFrom(t *testing.T, status string) string {
	t.Helper()
	const prefix = "Verification code: "
	i := strings.Index(status, prefix)
	if i < 0 {
		t.Fatalf("no code in %q", status)
	}
	return strings.Fields(status[i+len(prefix):])[0]
}

func TestPairAndConnect(t *testing.T) {
	addr, serverDir, requests, serverID := startPairServer(t, true, yes)
	clientDir := t.TempDir()

	if _, err := dialKnown(addr, clientDir); err == nil || !strings.Contains(err.Error(), "eco pair") {
		t.Fatalf("connect before pairing: %v", err)
	}
	var status bytes.Buffer
	if err := pairWith(addr, clientDir, "laptop", &status); err != nil {
		t.Fatal(err)
	}
	req := <-requests
	if got := codeFrom(t, status.String()); got != req.Code {
		t.Fatalf("codes differ: client %s server %s", got, req.Code)
	}
	if req.Name != "laptop" {
		t.Fatalf("name %q", req.Name)
	}
	clientID, _ := loadOrCreateIdentity(clientDir)
	if req.Fingerprint != ownFingerprint(clientID) {
		t.Fatal("server saw a different client fingerprint")
	}
	if fp, _ := knownServer(clientDir, addr); fp != ownFingerprint(serverID) {
		t.Fatal("server fingerprint not remembered")
	}
	if ok, _ := isAuthorized(serverDir, req.Fingerprint); !ok {
		t.Fatal("client not authorized")
	}
	cl := &Client{Addr: addr, Dir: clientDir}
	defer cl.Close()
	if err := cl.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPairDenied(t *testing.T) {
	addr, serverDir, requests, _ := startPairServer(t, true, no)
	clientDir := t.TempDir()
	err := pairWith(addr, clientDir, "intruder", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected denial: %v", err)
	}
	req := <-requests
	if ok, _ := isAuthorized(serverDir, req.Fingerprint); ok {
		t.Fatal("denied client was authorized")
	}
	if fp, _ := knownServer(clientDir, addr); fp != "" {
		t.Fatal("server remembered after denial")
	}
}

func TestPairingDisabled(t *testing.T) {
	addr, _, requests, _ := startPairServer(t, false, yes)
	err := pairWith(addr, t.TempDir(), "x", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected refusal: %v", err)
	}
	if len(requests) != 0 {
		t.Fatal("approval was requested although pairing is disabled")
	}
}

// An already authorized client pairing with the server again (for example through another address)
// must still be approved by a human, and must not be duplicated in authorized_clients.
func TestRepairingAuthorizedClientNeedsApproval(t *testing.T) {
	addr, serverDir, requests, _ := startPairServer(t, true, yes)
	clientDir := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := pairWith(addr, clientDir, "laptop", io.Discard); err != nil {
			t.Fatalf("pairing %d: %v", i, err)
		}
	}
	if len(requests) != 2 {
		t.Fatalf("expected 2 approval requests, got %d", len(requests))
	}
	rows, _ := readLines(filepath.Join(serverDir, "authorized_clients"))
	if len(rows) != 1 {
		t.Fatalf("authorized_clients has %d entries, want 1", len(rows))
	}
}

// Once paired, a client keeps working after the operator restarts the server without --pair.
func TestAuthorizedClientWorksWithPairingDisabled(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.cl.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUnauthorizedClientCannotExec(t *testing.T) {
	addr, _, _, serverID := startPairServer(t, true, yes)
	id, err := loadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.Dial("tcp", addr, clientTLS(id, ownFingerprint(serverID)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := writeFrame(c, fOpen, 1, mustJSON(openReq{Method: "exec", Executable: os.Args[0]})); err != nil {
		t.Fatal(err)
	}
	f, err := readFrame(c)
	if err != nil || f.typ != fError || !strings.Contains(string(f.payload), "not authorized") {
		t.Fatalf("got %+v %v", f, err)
	}
}

func TestServerFingerprintPinned(t *testing.T) {
	addr, _, _, _ := startPairServer(t, true, yes)
	clientDir := t.TempDir()
	if err := saveKnownServer(clientDir, addr, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := dialKnown(addr, clientDir); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("pin not enforced: %v", err)
	}
}

func TestPairingLocksAfterFailures(t *testing.T) {
	addr, _, _, _ := startPairServer(t, true, no)
	for i := 0; i < maxPairFailures; i++ {
		if err := pairWith(addr, t.TempDir(), "x", io.Discard); err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := pairWith(addr, t.TempDir(), "x", io.Discard); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("expected lock: %v", err)
	}
}

// A machine in the middle terminates TLS on both sides; the two codes must differ so the human notices.
func TestMachineInTheMiddleShowsDifferentCodes(t *testing.T) {
	addr, _, requests, _ := startPairServer(t, true, no)
	mitmID, err := loadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS(mitmID))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		in, err := l.Accept()
		if err != nil {
			return
		}
		out, err := tls.Dial("tcp", addr, clientTLS(mitmID, ""))
		if err != nil {
			in.Close()
			return
		}
		go io.Copy(out, in)
		io.Copy(in, out)
		in.Close()
		out.Close()
	}()
	var status bytes.Buffer
	_ = pairWith(l.Addr().String(), t.TempDir(), "victim", &status)
	req := <-requests
	if codeFrom(t, status.String()) == req.Code {
		t.Fatal("client and server saw the same code through a machine in the middle")
	}
}

func TestIdentityIsStableAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	a, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateIdentity(dir)
	if err != nil || ownFingerprint(a) != ownFingerprint(b) {
		t.Fatal("identity changed between loads")
	}
	if err := os.Remove(filepath.Join(dir, "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateIdentity(dir); err == nil {
		t.Fatal("regenerated a half-missing identity instead of failing")
	}
}
