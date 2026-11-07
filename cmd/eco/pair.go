package main

// Pairing-based trust, in the style of SSH known_hosts/authorized_keys.
//
// Every machine owns a self-signed identity (key.pem/cert.pem) that is created on first use.
// Trust is established once with `eco pair`: both sides display the same short code derived from
// the TLS session (a short authentication string bound to both identities); the server operator
// compares it with the client screen and approves. The server then remembers the client
// fingerprint (authorized_clients) and the client remembers the server fingerprint
// (known_servers). No CA and no file copying is needed.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	handshakeTimeout = 10 * time.Second
	approvalTimeout  = 60 * time.Second
	maxPairFailures  = 5
	pairLabel        = "eco pairing"
)

// stateDir returns the directory holding identity and trust files.
func stateDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("ECO_HOME"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".eco"), nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// loadOrCreateIdentity loads key.pem/cert.pem from dir, generating a self-signed identity if neither exists.
func loadOrCreateIdentity(dir string) (tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, err
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		return tls.LoadX509KeyPair(certPath, keyPath)
	case certErr == nil || keyErr == nil:
		return tls.Certificate{}, errors.New("incomplete identity in " + dir + ": need both cert.pem and key.pem")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	host, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "eco " + host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Key first, exclusively: never overwrite an existing secret.
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func ownFingerprint(c tls.Certificate) string { return fingerprint(c.Certificate[0]) }

// serverTLS asks for a client certificate but does not validate it: authorization is decided by
// fingerprint after the handshake, so unknown clients can reach the pairing path.
func serverTLS(id tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{id}, ClientAuth: tls.RequireAnyClientCert}
}

// clientTLS pins the server fingerprint. An empty pin accepts any server and is only for `eco pair`,
// where the short authentication string authenticates the peer.
func clientTLS(id tls.Certificate, pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{id},
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			if pin != "" && fingerprint(cs.PeerCertificates[0].Raw) != pin {
				return errors.New("server identity changed: fingerprint mismatch (possible impersonation); run `eco pair` again only if you trust the new server")
			}
			return nil
		},
	}
}

// sasCode derives the short authentication string both sides show. It is bound to this TLS session
// (exporter secret) and to both identities, so a machine-in-the-middle yields different codes.
func sasCode(cs tls.ConnectionState, serverFP, clientFP string) (string, error) {
	km, err := cs.ExportKeyingMaterial(pairLabel, nil, 32)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(km)
	h.Write([]byte(serverFP))
	h.Write([]byte(clientFP))
	n := binary.BigEndian.Uint32(h.Sum(nil)[:4]) % 100000000
	return fmt.Sprintf("%04d-%04d", n/10000, n%10000), nil
}

func cleanLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// --- trust files ---

func readLines(path string) ([][]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Split(line, "\t"))
	}
	return out, nil
}

func isAuthorized(dir, fp string) (bool, error) {
	rows, err := readLines(filepath.Join(dir, "authorized_clients"))
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r[0] == fp {
			return true, nil
		}
	}
	return false, nil
}

func authorize(dir, fp, name string) error {
	f, err := os.OpenFile(filepath.Join(dir, "authorized_clients"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s\t%s\t%s\n", fp, cleanLabel(name), time.Now().UTC().Format(time.RFC3339))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func knownServer(dir, addr string) (string, error) {
	rows, err := readLines(filepath.Join(dir, "known_servers"))
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if len(r) >= 2 && r[0] == addr {
			return r[1], nil
		}
	}
	return "", nil
}

func saveKnownServer(dir, addr, fp string) error {
	path := filepath.Join(dir, "known_servers")
	rows, err := readLines(path)
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, r := range rows {
		if len(r) >= 2 && r[0] != addr {
			fmt.Fprintf(&b, "%s\t%s\n", r[0], r[1])
		}
	}
	fmt.Fprintf(&b, "%s\t%s\n", addr, fp)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- server side ---

type pairRequest struct{ Name, Remote, Fingerprint, Code string }

type pairServer struct {
	dir      string
	fp       string // this server's own identity fingerprint
	enabled  bool
	approve  func(pairRequest) bool
	mux      *muxServer
	once     sync.Once
	mu       sync.Mutex
	busy     bool
	failures int
}

func (p *pairServer) serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go p.handle(c)
	}
}

func (p *pairServer) handle(c net.Conn) {
	p.once.Do(func() {
		if p.mux == nil {
			p.mux = newMuxServer()
		}
	})
	tc, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tc.Handshake(); err != nil {
		return
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return
	}
	clientFP := fingerprint(cs.PeerCertificates[0].Raw)
	authorized, err := isAuthorized(p.dir, clientFP)
	if err != nil {
		sendErrFrame(tc, 0, "cannot read authorized clients")
		return
	}
	if authorized {
		_ = tc.SetDeadline(time.Time{}) // established clients may stay idle
	}
	// Clients always speak first. A "pair" request is handled here even for authorized clients, because
	// pairing with a new server address must still be verified by a human on the server.
	br := bufio.NewReaderSize(tc, 64*1024)
	first, err := readFrame(br)
	if err != nil {
		return
	}
	var q openReq
	isPair := first.typ == fOpen && json.Unmarshal(first.payload, &q) == nil && q.Method == "pair"
	if !isPair {
		if !authorized {
			sendErrFrame(tc, first.stream, "not authorized; run `eco pair` on the client first (the server must run with --pair)")
			return
		}
		p.mux.serveConn(tc, br, clientFP, &first)
		return
	}
	id := first.stream
	if !p.enabled {
		sendErrFrame(tc, id, "pairing is disabled; start the server with --pair")
		return
	}
	p.mu.Lock()
	if p.busy || p.failures >= maxPairFailures {
		locked := p.failures >= maxPairFailures
		p.mu.Unlock()
		msg := "another pairing is in progress"
		if locked {
			msg = "pairing locked after too many failed attempts; restart the server"
		}
		sendErrFrame(tc, id, msg)
		return
	}
	p.busy = true
	p.mu.Unlock()
	approved := false
	defer func() {
		p.mu.Lock()
		p.busy = false
		if approved {
			p.failures = 0
		} else {
			p.failures++
		}
		p.mu.Unlock()
	}()
	code, err := sasCode(cs, p.fp, clientFP)
	if err != nil {
		sendErrFrame(tc, id, "cannot derive pairing code")
		return
	}
	_ = tc.SetDeadline(time.Time{})
	approved = p.approve(pairRequest{Name: cleanLabel(q.Name), Remote: tc.RemoteAddr().String(), Fingerprint: clientFP, Code: code})
	_ = tc.SetDeadline(time.Now().Add(handshakeTimeout))
	if !approved {
		sendErrFrame(tc, id, "pairing denied")
		return
	}
	if !authorized {
		if err := authorize(p.dir, clientFP, q.Name); err != nil {
			approved = false
			sendErrFrame(tc, id, "cannot store authorization")
			return
		}
	}
	_ = writeFrame(tc, fExit, id, mustJSON(exitInfo{}))
}

// stdinPrompt asks the operator on the terminal and waits for a yes/no answer.
var (
	stdinOnce  sync.Once
	stdinLines chan string
)

func promptApprove(r pairRequest) bool {
	stdinOnce.Do(func() {
		stdinLines = make(chan string)
		go func() {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				stdinLines <- sc.Text()
			}
			close(stdinLines)
		}()
	})
	for drained := false; !drained; { // discard stale input typed before the prompt
		select {
		case <-stdinLines:
		default:
			drained = true
		}
	}
	fmt.Fprintf(os.Stderr, "\nPairing request\n  machine:     %s (%s)\n  fingerprint: %s\n  code:        %s\nDoes the client show the same code? Approve [y/N] (%ds): ",
		r.Name, r.Remote, r.Fingerprint, r.Code, int(approvalTimeout/time.Second))
	select {
	case line, ok := <-stdinLines:
		if !ok {
			fmt.Fprintln(os.Stderr, "\nstdin closed; cannot approve")
			return false
		}
		a := strings.ToLower(strings.TrimSpace(line))
		return a == "y" || a == "yes" || a == "s" || a == "si"
	case <-time.After(approvalTimeout):
		fmt.Fprintln(os.Stderr, "\ntimed out")
		return false
	}
}

// --- client side ---

// pairWith runs the client half of pairing against addr and records the server fingerprint on success.
// status receives the verification code as soon as it is known.
func pairWith(addr, dir, label string, status io.Writer) error {
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		return err
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, clientTLS(id, ""))
	if err != nil {
		return err
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	srvFP := fingerprint(cs.PeerCertificates[0].Raw)
	code, err := sasCode(cs, srvFP, ownFingerprint(id))
	if err != nil {
		return err
	}
	fmt.Fprintf(status, "Verification code: %s\nServer fingerprint: %s\nCheck that the server shows the same code, then approve there (%ds)...\n", code, srvFP, int(approvalTimeout/time.Second))
	if label == "" {
		label, _ = os.Hostname()
	}
	if err := writeFrame(conn, fOpen, 1, mustJSON(openReq{Method: "pair", Name: cleanLabel(label)})); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(approvalTimeout + 2*handshakeTimeout))
	f, err := readFrame(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("no answer from server: %w", err)
	}
	switch f.typ {
	case fExit:
	case fError:
		return decodeErr(f)
	default:
		return errors.New("unexpected answer from server")
	}
	if err := saveKnownServer(dir, addr, srvFP); err != nil {
		return err
	}
	fmt.Fprintf(status, "Paired with %s.\n", addr)
	return nil
}

// dialKnown connects to a previously paired server, pinning its fingerprint.
func dialKnown(addr, dir string) (*tls.Conn, error) {
	pin, err := knownServer(dir, addr)
	if err != nil {
		return nil, err
	}
	if pin == "" {
		return nil, errors.New("unknown server " + addr + ": run `eco pair --addr " + addr + "` first")
	}
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		return nil, err
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, clientTLS(id, pin))
}
