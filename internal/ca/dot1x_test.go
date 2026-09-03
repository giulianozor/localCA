package ca

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

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
