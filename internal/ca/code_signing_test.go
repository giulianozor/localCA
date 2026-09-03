package ca

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

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
