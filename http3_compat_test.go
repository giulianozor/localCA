package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHTTP3TLSCertCompatibility verifies that the CA and issued server
// certificate generated through the real code paths satisfy the requirements
// for serving HTTPS and HTTP/3 (QUIC, RFC 9114) from a Go server in local
// development.
func TestHTTP3TLSCertCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Local Dev CA", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("localhost", []string{
		"localhost",
		"127.0.0.1",
		"::1",
	}, 1, "", "", a.hasIntermediate()); err != nil {
		t.Fatalf("createServerCert() error = %v", err)
	}

	certDir := filepath.Join(tempDir, "certs")
	entries, err := os.ReadDir(certDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one issued cert, got %v (err=%v)", entries, err)
	}
	issuedDir := filepath.Join(certDir, entries[0].Name())

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(issuedDir, "cert.pem"),
		filepath.Join(issuedDir, "key.pem"),
	)
	if err != nil {
		t.Fatalf("load issued keypair: %v", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(tempDir, "ca-cert.pem"))
	if err != nil {
		t.Fatalf("read ca-cert.pem: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to append CA to pool")
	}

	tlsCert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	// ---- Certificate content requirements ----
	if len(tlsCert.ExtKeyUsage) == 0 {
		t.Fatal("server cert has no ExtKeyUsage")
	}
	if !containsExtKeyUsage(tlsCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("server cert missing ExtKeyUsageServerAuth")
	}
	if tlsCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("server cert missing KeyUsageDigitalSignature")
	}
	if tlsCert.SignatureAlgorithm == x509.SHA1WithRSA || tlsCert.SignatureAlgorithm == x509.MD5WithRSA {
		t.Fatalf("server cert uses insecure signature algorithm %v", tlsCert.SignatureAlgorithm)
	}
	if err := tlsCert.VerifyHostname("localhost"); err != nil {
		t.Fatalf("cert does not verify for localhost: %v", err)
	}
	if err := tlsCert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("cert does not verify for 127.0.0.1: %v", err)
	}
	// Chain validation against our CA pool.
	if _, err := tlsCert.Verify(x509.VerifyOptions{
		Roots:   pool,
		DNSName: "localhost",
	}); err != nil {
		t.Fatalf("cert chain does not verify against CA: %v", err)
	}

	// ---- Real TLS 1.3 handshake (the foundation HTTP/3 uses) ----
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
		// ALPN as required by HTTP/3 (RFC 9114/QUIC-TLS).
		NextProtos: []string{"h3"},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			ts := tls.Server(conn, serverTLS)
			if err := ts.Handshake(); err != nil {
				ts.Close()
				continue
			}
			ts.Close()
			conn.Close()
		}
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
	}
	addr := ln.Addr().String()
	done := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", addr, clientTLS)
		if err != nil {
			done <- err
			return
		}
		cs := c.ConnectionState()
		c.Close()
		if cs.NegotiatedProtocol != "h3" {
			done <- fmt.Errorf("negotiated ALPN %q, want h3", cs.NegotiatedProtocol)
			return
		}
		if cs.Version != tls.VersionTLS13 {
			done <- fmt.Errorf("negotiated TLS version %d, want TLS 1.3 (%d)", cs.Version, tls.VersionTLS13)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("TLS 1.3 / h3 handshake: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handshake")
	}

	// ---- CA cert sanity ----
	caCert := parseCertificatePEM(t, filepath.Join(tempDir, "ca-cert.pem"))
	if caCert.SignatureAlgorithm == x509.SHA1WithRSA || caCert.SignatureAlgorithm == x509.MD5WithRSA {
		t.Fatalf("CA uses insecure signature algorithm %v", caCert.SignatureAlgorithm)
	}
}

func containsExtKeyUsage(usages []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, u := range usages {
		if u == want {
			return true
		}
	}
	return false
}
