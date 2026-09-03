package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/giulianozor/localCA/internal/ca"
)

func TestExportClientCertP12(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("alice@example.com", nil, 1, "", "", false, "client"); err != nil {
		t.Fatalf("CreateServerCert(client) error = %v", err)
	}
	certs, _ := a.ListCerts()
	id := certs[0].ID
	certDir := filepath.Join(a.DataDir, "certs", id)

	rr := httptest.NewRecorder()
	// Direct helper call.
	req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+id+"&export_passphrase=p12pass", nil)
	handleDownload(a, rr, req)
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
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	// Client cert with an encrypted private key.
	if err := a.CreateServerCert("bob@example.com", nil, 1, "keypass", "", false, "client"); err != nil {
		t.Fatalf("CreateServerCert(client, keypass) error = %v", err)
	}
	certs, _ := a.ListCerts()
	id := certs[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+id, nil)
	handleDownload(a, rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for encrypted-key p12 export, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "encrypted") {
		t.Fatalf("expected error mentioning encrypted key, got %q", rr.Body.String())
	}
}
