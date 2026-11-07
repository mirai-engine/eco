package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cert(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, parsed, key
}
func TestTLSAndProtocol(t *testing.T) {
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	_, ca, caKey := cert(t, caTemplate, nil, nil)
	serverCert, _, _ := cert(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"eco.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, caKey)
	clientCert, _, _ := cert(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go serveConn(c)
		}
	}()
	_, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "wrong.test", Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13})
	if err == nil {
		t.Fatal("server with wrong name was accepted")
	}
	unauthed, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "eco.test", MinVersion: tls.VersionTLS13})
	if err == nil {
		_ = unauthed.SetDeadline(time.Now().Add(time.Second))
		_, _ = unauthed.Write([]byte("{}\n"))
		var one [1]byte
		_, err = unauthed.Read(one[:])
		_ = unauthed.Close()
	}
	if err == nil {
		t.Fatal("client without certificate was accepted")
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "eco.test", Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	enc := json.NewEncoder(c)
	dec := json.NewDecoder(bufio.NewReader(c))
	if err = enc.Encode(request{ID: "p", Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var e event
	if err = dec.Decode(&e); err != nil || e.Type != "pong" || e.ID != "p" {
		t.Fatalf("ping: %+v %v", e, err)
	}
	if err = enc.Encode(request{ID: "p", Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	if err = dec.Decode(&e); err != nil || e.Type != "error" {
		t.Fatalf("duplicate: %+v %v", e, err)
	}
	if err = enc.Encode(request{ID: "run", Method: "exec", Executable: os.Args[0], Args: []string{"-test.run=TestChild"}}); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	foundExit := false
	for !foundExit {
		e = event{}
		if err = dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		switch e.Type {
		case "stdout":
			output.Write(e.Data)
		case "exit":
			foundExit = true
			if e.ExitCode == nil || *e.ExitCode != 0 {
				t.Fatalf("exit: %+v", e)
			}
		case "error":
			t.Fatal(e.Error)
		}
	}
	if !strings.Contains(output.String(), "eco-child") {
		t.Fatalf("missing output: %q", output.String())
	}
}
func TestChild(t *testing.T) { fmt.Println("eco-child") }

func TestSetup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := setup(dir); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "client", "ca.pem")
	if _, err := tlsConfig(filepath.Join(dir, "client", "cert.pem"), filepath.Join(dir, "client", "key.pem"), ca, false, "eco.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConfig(filepath.Join(dir, "server", "cert.pem"), filepath.Join(dir, "server", "key.pem"), filepath.Join(dir, "server", "ca.pem"), true, ""); err != nil {
		t.Fatal(err)
	}
	if err := setup(dir); err == nil {
		t.Fatal("overwrote existing credentials")
	}
}
