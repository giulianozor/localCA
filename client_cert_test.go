package main

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestCreateClientCertificate(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	// Client certificate with no SANs (identity is the CommonName).
	if err := a.createServerCert("alice@example.com", nil, 1, "", "", false, true); err != nil {
		t.Fatalf("createServerCert(client) error = %v", err)
	}

	certs, err := a.listCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	meta := certs[0]
	if !meta.Client {
		t.Fatal("expected metadata Client=true for client certificate")
	}

	cert := parseCertificatePEM(t, filepath.Join(a.dataDir, "certs", meta.ID, "cert.pem"))
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
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("alice@example.com", nil, 1, "", "", false, true); err != nil {
		t.Fatalf("createServerCert(client) error = %v", err)
	}
	certs, _ := a.listCerts()
	meta := certs[0]

	// Renew using the stored metadata (same code path as the renew handler).
	if err := a.createServerCert(meta.CommonName, meta.SANs, meta.ValidityYears, "", "", false, meta.Client); err != nil {
		t.Fatalf("renew client cert error = %v", err)
	}

	renewed, err := a.listCerts()
	if err != nil || len(renewed) != 2 {
		t.Fatalf("expected 2 certs after renew, got %d (err=%v)", len(renewed), err)
	}
	for _, c := range renewed {
		if c.ID != meta.ID && !c.Client {
			t.Fatalf("renewed certificate %s lost the client flag", c.ID)
		}
	}
}

func TestExportClientCertP12(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("alice@example.com", nil, 1, "", "", false, true); err != nil {
		t.Fatalf("createServerCert(client) error = %v", err)
	}
	certs, _ := a.listCerts()
	id := certs[0].ID
	certDir := filepath.Join(a.dataDir, "certs", id)

	rr := httptest.NewRecorder()
	// Direct helper call.
	req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+id+"&export_passphrase=p12pass", nil)
	a.handleDownload(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("client-p12 download status = %d, want %d (body=%s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "pkcs12") {
		t.Fatalf("Content-Type = %q, want pkcs12", rr.Header().Get("Content-Type"))
	}

	// Decode the produced p12 and confirm it matches the leaf certificate.
	pfx := rr.Body.Bytes()
	privKey, leaf, caCerts, err := pkcs12.DecodeChain(pfx, "p12pass")
	if err != nil {
		t.Fatalf("pkcs12 decode error = %v", err)
	}
	if leaf == nil || privKey == nil {
		t.Fatal("p12 did not decode a key and certificate")
	}
	if len(caCerts) == 0 {
		t.Fatal("p12 did not include the CA certificate chain")
	}
	diskCert := parseCertificatePEM(t, filepath.Join(certDir, "cert.pem"))
	if leaf.SerialNumber.Cmp(diskCert.SerialNumber) != 0 {
		t.Fatal("p12 leaf certificate does not match stored certificate")
	}

	// Wrong password must fail.
	if _, _, _, err := pkcs12.DecodeChain(pfx, "wrong"); err == nil {
		t.Fatal("p12 decoded with wrong password, want error")
	}
}

func TestExportClientCertP12RequiresUnencryptedKey(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	// Client cert with an encrypted private key.
	if err := a.createServerCert("bob@example.com", nil, 1, "keypass", "", false, true); err != nil {
		t.Fatalf("createServerCert(client, keypass) error = %v", err)
	}
	certs, _ := a.listCerts()
	id := certs[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+id, nil)
	a.handleDownload(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for encrypted-key p12 export, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "encrypted") {
		t.Fatalf("expected error mentioning encrypted key, got %q", rr.Body.String())
	}
}
