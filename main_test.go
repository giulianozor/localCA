package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giulianozor/localCA/internal/ca"
)

func TestParseArgs(t *testing.T) {
	t.Run("default port", func(t *testing.T) {
		dataDir, port, lang, err := parseArgs([]string{"/tmp/data"})
		if err != nil {
			t.Fatalf("parseArgs() error = %v", err)
		}
		if dataDir != "/tmp/data" {
			t.Fatalf("parseArgs() dataDir = %s, want /tmp/data", dataDir)
		}
		if port != 8080 {
			t.Fatalf("parseArgs() port = %d, want 8080", port)
		}
		if lang != "en" {
			t.Fatalf("parseArgs() lang = %s, want en", lang)
		}
	})

	t.Run("custom port", func(t *testing.T) {
		_, port, lang, err := parseArgs([]string{"-port", "9443", "-lang", "it", "/tmp/data"})
		if err != nil {
			t.Fatalf("parseArgs() error = %v", err)
		}
		if port != 9443 {
			t.Fatalf("parseArgs() port = %d, want 9443", port)
		}
		if lang != "it" {
			t.Fatalf("parseArgs() lang = %s, want it", lang)
		}
	})

	t.Run("invalid port", func(t *testing.T) {
		if _, _, _, err := parseArgs([]string{"-port", "70000", "/tmp/data"}); err == nil {
			t.Fatal("parseArgs() expected error")
		}
	})

	t.Run("invalid language", func(t *testing.T) {
		if _, _, _, err := parseArgs([]string{"-lang", "fr", "/tmp/data"}); err == nil {
			t.Fatal("parseArgs() expected error")
		}
	})
}

func TestHandleDownloadSupportsCSRAndArchive(t *testing.T) {
	a, certID := createTestCertificate(t)

	t.Run("csr pem", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/download?kind=csr-pem&id="+certID, nil)
		rr := httptest.NewRecorder()

		handleDownload(a, rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("handleDownload() status = %d, want %d", rr.Code, http.StatusOK)
		}
		if !strings.Contains(rr.Header().Get("Content-Disposition"), certID+"-csr.pem") {
			t.Fatalf("Content-Disposition = %q, want csr filename", rr.Header().Get("Content-Disposition"))
		}
		if !strings.Contains(rr.Body.String(), "BEGIN CERTIFICATE REQUEST") {
			t.Fatalf("CSR response did not contain PEM request, got %q", rr.Body.String())
		}
	})

	t.Run("archive", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/download?kind=all-tar-gz&id="+certID, nil)
		rr := httptest.NewRecorder()

		handleDownload(a, rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("handleDownload() status = %d, want %d", rr.Code, http.StatusOK)
		}
		if !strings.Contains(rr.Header().Get("Content-Disposition"), certID+".tar.gz") {
			t.Fatalf("Content-Disposition = %q, want archive filename", rr.Header().Get("Content-Disposition"))
		}

		gzipReader, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
		if err != nil {
			t.Fatalf("gzip.NewReader() error = %v", err)
		}
		defer gzipReader.Close()

		tarReader := tar.NewReader(gzipReader)
		names := map[string]bool{}
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("tarReader.Next() error = %v", err)
			}
			names[header.Name] = true
		}

		for _, name := range []string{"cert.pem", "chain.pem", "csr.pem", "key.pem", "metadata.json", "ca-cert.pem", "issuer-chain.pem"} {
			if !names[name] {
				t.Fatalf("archive missing %s; got %#v", name, names)
			}
		}
	})
}

func TestRevokeAndRenewCertificate(t *testing.T) {
	a, certID := createTestCertificate(t)
	revokeForm := url.Values{}
	revokeForm.Set("id", certID)
	revokeReq := httptest.NewRequest(http.MethodPost, "/certs/revoke", strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRR := httptest.NewRecorder()
	handleRevokeCert(a, revokeRR, revokeReq)
	if revokeRR.Code != http.StatusSeeOther {
		t.Fatalf("handleRevokeCert() status = %d, want %d", revokeRR.Code, http.StatusSeeOther)
	}
	certDir := filepath.Join(a.DataDir, "certs", certID)
	meta, err := a.LoadCertMetadata(certDir)
	if err != nil {
		t.Fatalf("LoadCertMetadata() error = %v", err)
	}
	if meta.RevokedAt == nil {
		t.Fatal("expected certificate to be revoked")
	}

	renewForm := url.Values{}
	renewForm.Set("id", certID)
	renewReq := httptest.NewRequest(http.MethodPost, "/certs/renew", strings.NewReader(renewForm.Encode()))
	renewReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	renewRR := httptest.NewRecorder()
	handleRenewCert(a, renewRR, renewReq)
	if renewRR.Code != http.StatusSeeOther {
		t.Fatalf("handleRenewCert() status = %d, want %d", renewRR.Code, http.StatusSeeOther)
	}
	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("ListCerts() len = %d, want 2 after renewal", len(certs))
	}
}

func TestHandleDownloadArchiveRejectsExportPassphraseForEncryptedKey(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &ca.App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("leaf.local", []string{"leaf.local"}, 1, "leaf-pass", "", a.HasIntermediate(), "server"); err != nil {
		t.Fatalf("CreateServerCert() error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/download?kind=all-tar-gz&id="+certs[0].ID+"&export_passphrase=export-pass", nil)
	rr := httptest.NewRecorder()
	handleDownload(a, rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("handleDownload() status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestHandleGenerateCRL(t *testing.T) {
	translations, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	a, certID := createTestCertificate(t)
	a.Translations = translations

	// Revoke via handler
	revokeForm := url.Values{}
	revokeForm.Set("id", certID)
	revokeReq := httptest.NewRequest(http.MethodPost, "/certs/revoke", strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRR := httptest.NewRecorder()
	handleRevokeCert(a, revokeRR, revokeReq)
	if revokeRR.Code != http.StatusSeeOther {
		t.Fatalf("handleRevokeCert() status = %d, want %d", revokeRR.Code, http.StatusSeeOther)
	}

	// Generate CRL via handler
	genReq := httptest.NewRequest(http.MethodPost, "/certs/crl/generate", strings.NewReader(""))
	genReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	genRR := httptest.NewRecorder()
	handleGenerateCRL(a, genRR, genReq)
	if genRR.Code != http.StatusSeeOther {
		t.Fatalf("handleGenerateCRL() status = %d, want %d", genRR.Code, http.StatusSeeOther)
	}
	if !strings.Contains(genRR.Header().Get("Location"), "msg=") {
		t.Fatalf("handleGenerateCRL() expected success redirect, got %s", genRR.Header().Get("Location"))
	}

	// Verify CRL file was created
	if _, err := os.Stat(filepath.Join(a.DataDir, "crl.pem")); err != nil {
		t.Fatalf("crl.pem not created: %v", err)
	}

	// Download CRL via handler
	dlReq := httptest.NewRequest(http.MethodGet, "/download?kind=crl-pem", nil)
	dlRR := httptest.NewRecorder()
	handleDownload(a, dlRR, dlReq)
	if dlRR.Code != http.StatusOK {
		t.Fatalf("handleDownload(crl-pem) status = %d, want %d", dlRR.Code, http.StatusOK)
	}
	if dlRR.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("handleDownload(crl-pem) Content-Type = %s", dlRR.Header().Get("Content-Type"))
	}
}

func TestHandleRenewCAHandler(t *testing.T) {
	translations, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &ca.App{DataDir: tempDir, DefaultLang: "en", Translations: translations}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/ca/renew", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRenewCA(a, rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleRenewCA() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if !strings.Contains(rr.Header().Get("Location"), "msg=") {
		t.Fatalf("handleRenewCA() expected success redirect, got %s", rr.Header().Get("Location"))
	}
}

func TestHandleRenewIntermediateHandler(t *testing.T) {
	translations, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &ca.App{DataDir: tempDir, DefaultLang: "en", Translations: translations}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/intermediate/renew", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRenewIntermediate(a, rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleRenewIntermediate() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if !strings.Contains(rr.Header().Get("Location"), "msg=") {
		t.Fatalf("handleRenewIntermediate() expected success redirect, got %s", rr.Header().Get("Location"))
	}
}

func TestHandleRenewCARequiresPassphrase(t *testing.T) {
	translations, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &ca.App{DataDir: tempDir, DefaultLang: "en", Translations: translations}
	if err := a.CreateCA("Test Root", "localCA", "IT", "secret"); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/ca/renew", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRenewCA(a, rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleRenewCA() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if !strings.Contains(rr.Header().Get("Location"), "err=") {
		t.Fatalf("handleRenewCA() expected error redirect when passphrase missing, got %s", rr.Header().Get("Location"))
	}
}

func TestHandleRenewIntermediateRequiresPassphrase(t *testing.T) {
	translations, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &ca.App{DataDir: tempDir, DefaultLang: "en", Translations: translations}
	if err := a.CreateCA("Test Root", "localCA", "IT", "secret"); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "secret", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/intermediate/renew", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleRenewIntermediate(a, rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleRenewIntermediate() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if !strings.Contains(rr.Header().Get("Location"), "err=") {
		t.Fatalf("handleRenewIntermediate() expected error redirect when passphrase missing, got %s", rr.Header().Get("Location"))
	}
}

func createTestCertificate(t *testing.T) (*ca.App, string) {
	t.Helper()

	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &ca.App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("myserver.example.com", []string{
		"myserver.example.com",
		"myserver.internal",
		"192.168.1.100",
		"10.0.0.50",
		"127.0.0.1",
	}, 1, "", "", a.HasIntermediate(), "server"); err != nil {
		t.Fatalf("CreateServerCert() error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("ListCerts() len = %d, want 1", len(certs))
	}
	return a, certs[0].ID
}

func parseCertificatePEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s did not contain a PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%s) error = %v", path, err)
	}
	return cert
}

func assertIPAddresses(t *testing.T, got []net.IP, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("IPAddresses len = %d, want %d", len(got), len(want))
	}
	for i, expected := range want {
		if got[i].String() != expected {
			t.Fatalf("IPAddresses[%d] = %s, want %s", i, got[i], expected)
		}
	}
}
