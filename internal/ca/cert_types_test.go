package ca

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

func TestCreateClientCertificate(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	// Client certificate with no SANs (identity is the CommonName).
	if err := a.CreateServerCert("alice@example.com", nil, 1, "", "", false, "client"); err != nil {
		t.Fatalf("CreateServerCert(client) error = %v", err)
	}

	certs, err := a.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	meta := certs[0]
	if meta.CertType() != "client" {
		t.Fatal("expected metadata type=client for client certificate")
	}

	cert := parseCertificatePEM(t, filepath.Join(a.DataDir, "certs", meta.ID, "cert.pem"))
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatal("client certificate missing ExtKeyUsageClientAuth")
	}
	if containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("client certificate should not include ExtKeyUsageServerAuth")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("client certificate missing KeyUsageDigitalSignature")
	}
}

func TestRenewClientCertificatePreservesClientFlag(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("alice@example.com", nil, 1, "", "", false, "client"); err != nil {
		t.Fatalf("CreateServerCert(client) error = %v", err)
	}
	certs, _ := a.ListCerts()
	meta := certs[0]

	// Renew using the stored metadata (same code path as the renew handler).
	if err := a.CreateServerCert(meta.CommonName, meta.SANs, meta.ValidityYears, "", "", false, meta.CertType()); err != nil {
		t.Fatalf("renew client cert error = %v", err)
	}

	renewed, err := a.ListCerts()
	if err != nil || len(renewed) != 2 {
		t.Fatalf("expected 2 certs after renew, got %d (err=%v)", len(renewed), err)
	}
	for _, c := range renewed {
		if c.ID != meta.ID && c.CertType() != "client" {
			t.Fatalf("renewed certificate %s lost the client type", c.ID)
		}
	}
}

func TestCreateDot1xCertificate(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	// 802.1X (EAP-TLS) zero-touch onboarding device, no SANs (identity is CN).
	if err := a.CreateServerCert("device-07ab", nil, 1, "", "", false, "dot1x"); err != nil {
		t.Fatalf("CreateServerCert(dot1x) error = %v", err)
	}

	certs, err := a.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	meta := certs[0]
	if meta.CertType() != "dot1x" {
		t.Fatalf("metadata type = %q, want dot1x", meta.CertType())
	}

	cert := parseCertificatePEM(t, filepath.Join(a.DataDir, "certs", meta.ID, "cert.pem"))
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatal("802.1X certificate missing ExtKeyUsageClientAuth")
	}
	if containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("802.1X certificate should not include ExtKeyUsageServerAuth")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("802.1X certificate missing KeyUsageDigitalSignature")
	}
}

func TestCreateCodeSigningCertificate(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("CI Signing Key", nil, 1, "", "", false, "codeSigning"); err != nil {
		t.Fatalf("CreateServerCert(codeSigning) error = %v", err)
	}

	certs, err := a.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	meta := certs[0]
	if meta.CertType() != "codeSigning" {
		t.Fatalf("metadata type = %q, want codeSigning", meta.CertType())
	}

	cert := parseCertificatePEM(t, filepath.Join(a.DataDir, "certs", meta.ID, "cert.pem"))
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		t.Fatal("code signing certificate missing ExtKeyUsageCodeSigning")
	}
	if containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatal("code signing certificate should not include client auth")
	}
	if containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("code signing certificate should not include server auth")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("code signing certificate missing KeyUsageDigitalSignature")
	}
}

func TestServerCertificateKeyUsage(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("srv.local", []string{"srv.local"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("CreateServerCert(server) error = %v", err)
	}
	certs, _ := a.ListCerts()
	meta := certs[0]
	cert := parseCertificatePEM(t, filepath.Join(a.DataDir, "certs", meta.ID, "cert.pem"))
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("server certificate missing ExtKeyUsageServerAuth")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("server certificate missing KeyUsageKeyEncipherment")
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
