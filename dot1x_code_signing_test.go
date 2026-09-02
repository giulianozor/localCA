package main

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateDot1xCertificate(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	// 802.1X (EAP-TLS) zero-touch onboarding device, no SANs (identity is CN).
	if err := a.createServerCert("device-07ab", nil, 1, "", "", false, "dot1x"); err != nil {
		t.Fatalf("createServerCert(dot1x) error = %v", err)
	}

	certs, err := a.listCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	meta := certs[0]
	if meta.CertType() != "dot1x" {
		t.Fatalf("metadata type = %q, want dot1x", meta.CertType())
	}

	cert := parseCertificatePEM(t, filepath.Join(a.dataDir, "certs", meta.ID, "cert.pem"))
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
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("CI Signing Key", nil, 1, "", "", false, "codeSigning"); err != nil {
		t.Fatalf("createServerCert(codeSigning) error = %v", err)
	}

	certs, err := a.listCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	meta := certs[0]
	if meta.CertType() != "codeSigning" {
		t.Fatalf("metadata type = %q, want codeSigning", meta.CertType())
	}

	cert := parseCertificatePEM(t, filepath.Join(a.dataDir, "certs", meta.ID, "cert.pem"))
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
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("srv.local", []string{"srv.local"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("createServerCert(server) error = %v", err)
	}
	certs, _ := a.listCerts()
	meta := certs[0]
	cert := parseCertificatePEM(t, filepath.Join(a.dataDir, "certs", meta.ID, "cert.pem"))
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("server certificate missing ExtKeyUsageServerAuth")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("server certificate missing KeyUsageKeyEncipherment")
	}
}

func TestExportDot1xCertP12(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("device-07ab", nil, 1, "", "", false, "dot1x"); err != nil {
		t.Fatalf("createServerCert(dot1x) error = %v", err)
	}
	certs, _ := a.listCerts()
	id := certs[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+id+"&export_passphrase=pass", nil)
	a.handleDownload(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("dot1x p12 download status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "pkcs12") {
		t.Fatalf("Content-Type = %q, want pkcs12", rr.Header().Get("Content-Type"))
	}
}
