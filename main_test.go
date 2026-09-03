package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

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

func TestRenewCertificateKeepsOriginalSigner(t *testing.T) {
	a, certID := createTestCertificate(t)
	// Create an intermediate AFTER the certificate: the cert is root-signed.
	// Renewing it must keep the root signer and not silently switch to the
	// intermediate (the current default signer).
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	certDir := filepath.Join(a.DataDir, "certs", certID)
	meta, err := a.LoadCertMetadata(certDir)
	if err != nil {
		t.Fatalf("LoadCertMetadata() error = %v", err)
	}
	if meta.Signer != "ca" {
		t.Fatalf("original cert signer = %q, want ca", meta.Signer)
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
	found := false
	for _, c := range certs {
		if c.ID == certID {
			continue // the revoked original
		}
		found = true
		if c.Signer != "ca" {
			t.Fatalf("renewed cert signer = %q, want ca (kept original root signer)", c.Signer)
		}
	}
	if !found {
		t.Fatal("renewed certificate not found")
	}
}

func TestRenewCertificateLegacyMetadataUsesDefaultValidity(t *testing.T) {
	a, certID := createTestCertificate(t)

	// Rewrite metadata without the validity_years field to simulate a cert
	// created before validity tracking. Renewing must not fail on years=0.
	meta, err := a.LoadCertMetadata(filepath.Join(a.DataDir, "certs", certID))
	if err != nil {
		t.Fatalf("LoadCertMetadata() error = %v", err)
	}
	var raw map[string]interface{}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if err := json.Unmarshal(metaBytes, &raw); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	delete(raw, "validity_years")
	legacyBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal legacy metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(a.DataDir, "certs", certID, "metadata.json"), legacyBytes, 0o640); err != nil {
		t.Fatalf("write legacy metadata: %v", err)
	}

	renewForm := url.Values{}
	renewForm.Set("id", certID)
	renewReq := httptest.NewRequest(http.MethodPost, "/certs/renew", strings.NewReader(renewForm.Encode()))
	renewReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	renewRR := httptest.NewRecorder()
	handleRenewCert(a, renewRR, renewReq)
	if renewRR.Code != http.StatusSeeOther {
		t.Fatalf("handleRenewCert() status = %d, want %d, location=%s", renewRR.Code, http.StatusSeeOther, renewRR.Header().Get("Location"))
	}

	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("ListCerts() len = %d, want 2 after successful legacy renewal", len(certs))
	}
}

func TestHandleChangeCertPassphraseLocalizedRequiredErrors(t *testing.T) {
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
	// Create a cert whose private key is passphrase-protected.
	if err := a.CreateServerCert("secure.local", []string{"secure.local"}, 1, "orig-pass", "", false, "server"); err != nil {
		t.Fatalf("CreateServerCert() error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	certID := certs[0].ID

	passForm := url.Values{}
	passForm.Set("id", certID)
	passForm.Set("current_passphrase", "")
	passForm.Set("new_passphrase", "new-pass")
	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/certs/passphrase", strings.NewReader(passForm.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}

	// Without a Translations map the localized key falls back to the key name.
	rr := httptest.NewRecorder()
	a.Translations = nil
	handleChangeCertPassphrase(a, rr, newReq())
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleChangeCertPassphrase() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if !strings.Contains(rr.Header().Get("Location"), "msg.cert_passphrase_required") {
		t.Fatalf("expected fallback key msg.cert_passphrase_required, got %s", rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	a.Translations = translations
	handleChangeCertPassphrase(a, rr, newReq())
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, url.QueryEscape("Certificate passphrase required")) {
		t.Fatalf("expected localized 'Certificate passphrase required', got %s", loc)
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

func TestHandleChangeIntermediatePassphraseRequiresCurrentPassphrase(t *testing.T) {
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
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "secret", "intermediate-secret"); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/intermediate/passphrase", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handleChangeIntermediatePassphrase(a, rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleChangeIntermediatePassphrase() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Fatalf("handleChangeIntermediatePassphrase() expected error redirect when current passphrase missing, got %s", loc)
	}
	if strings.Contains(loc, url.QueryEscape("Intermediate passphrase required")) {
		return
	}
	if !strings.Contains(loc, url.QueryEscape("Issuer key passphrase required")) {
		t.Fatalf("handleChangeIntermediatePassphrase() unexpected error message, got %s", loc)
	}
	t.Fatalf("handleChangeIntermediatePassphrase() used miscategorized signer_passphrase_required key: %s", loc)
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

// buildTestCA creates an app with a CA and one issued certificate so we can
// exercise whole-CA archive handler round-trips.
func buildTestCA(t *testing.T) (*ca.App, string) {
	t.Helper()
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("myserver.example.com", []string{
		"myserver.example.com", "127.0.0.1",
	}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("CreateServerCert() error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	return a, certs[0].ID
}

func TestHandleDownloadCAArchive(t *testing.T) {
	a, _ := buildTestCA(t)

	req := httptest.NewRequest(http.MethodGet, "/download?kind=ca-all-tar-gz&export_passphrase=backup-pass", nil)
	rr := httptest.NewRecorder()
	handleDownload(a, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handleDownload(ca-all-tar-gz) status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.Bytes()
	if !bytes.HasPrefix(body, []byte(ca.CAArchiveMagic)) {
		t.Fatal("exported CA archive was not encrypted despite passphrase")
	}

	// Download without passphrase should produce a plain tar.gz.
	req2 := httptest.NewRequest(http.MethodGet, "/download?kind=ca-all-tar-gz", nil)
	rr2 := httptest.NewRecorder()
	handleDownload(a, rr2, req2)
	if bytes.HasPrefix(rr2.Body.Bytes(), []byte(ca.CAArchiveMagic)) {
		t.Fatal("exported CA archive unexpectedly encrypted without passphrase")
	}
}

func TestHandleImportCA(t *testing.T) {
	src, certID := buildTestCA(t)
	raw, err := src.BuildCAArchive()
	if err != nil {
		t.Fatalf("BuildCAArchive() error = %v", err)
	}

	dst := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("archive", "backup.tar.gz")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(raw); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	if err := mw.WriteField("import_passphrase", ""); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("mw.Close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ca/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	handleImportCA(dst, rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleImportCA status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if got := rr.Header().Get("Location"); !strings.Contains(got, "msg=") {
		t.Fatalf("expected success redirect, got %q", got)
	}
	if _, err := os.Stat(filepath.Join(dst.DataDir, "certs", certID, "cert.pem")); err != nil {
		t.Fatalf("issued cert not restored after import: %v", err)
	}
}

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

func TestExportClientCertP12ChainMatchesSigner(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	// Root-signed client cert, created before the intermediate exists.
	if err := a.CreateServerCert("ca-leaf@example.com", nil, 1, "", "", false, "client"); err != nil {
		t.Fatalf("CreateServerCert(client, root) error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}
	// Intermediate-signed client cert.
	if err := a.CreateServerCert("int-leaf@example.com", nil, 1, "", "", true, "client"); err != nil {
		t.Fatalf("CreateServerCert(client, intermediate) error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("ListCerts() len = %d, want 2", len(certs))
	}

	for _, c := range certs {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+c.ID, nil)
		handleDownload(a, rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("client-p12 status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		_, _, caCerts, err := pkcs12.DecodeChain(rr.Body.Bytes(), pkcs12.DefaultPassword)
		if err != nil {
			t.Fatalf("pkcs12 decode %s error = %v", c.CommonName, err)
		}
		if c.Signer == "intermediate" {
			if len(caCerts) != 2 {
				t.Fatalf("intermediate-signed p12 caCerts = %d, want 2 (intermediate + root)", len(caCerts))
			}
		} else {
			if len(caCerts) != 1 {
				t.Fatalf("root-signed p12 caCerts = %d, want 1 (root only)", len(caCerts))
			}
		}
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

func TestExportDot1xCertP12(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("device-07ab", nil, 1, "", "", false, "dot1x"); err != nil {
		t.Fatalf("CreateServerCert(dot1x) error = %v", err)
	}
	certs, _ := a.ListCerts()
	id := certs[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+id+"&export_passphrase=pass", nil)
	handleDownload(a, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("dot1x p12 download status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "pkcs12") {
		t.Fatalf("Content-Type = %q, want pkcs12", rr.Header().Get("Content-Type"))
	}
}

func TestHandleCertTableFiltersByType(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("srv.local", nil, 1, "", "", false, "server"); err != nil {
		t.Fatalf("server cert error = %v", err)
	}
	if err := a.CreateServerCert("alice", nil, 1, "", "", false, "client"); err != nil {
		t.Fatalf("client cert error = %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/certs/table?type=client", nil)
	handleCertTable(a, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleCertTable status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alice") {
		t.Fatalf("table body missing client cert: %q", body)
	}
	if strings.Contains(body, "srv.local") {
		t.Fatalf("table body should not contain server cert in client view: %q", body)
	}

	// Unknown type is rejected.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/certs/table?type=bogus", nil)
	handleCertTable(a, rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown type, got %d", rr2.Code)
	}
}

func TestIndexRendersTabsAndPerTypeForms(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	tr, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	a.Translations = tr
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("myserver.example.com", []string{"myserver.example.com"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("server cert error = %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handleIndex(a, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleIndex status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	for _, marker := range []string{
		`class="tabs js-tabs"`,
		`data-tab="ca"`,
		`data-tab="server"`,
		`data-tab="client"`,
		`data-tab="dot1x"`,
		`data-tab="code"`,
		`id="tab-ca"`,
		`id="tab-server"`,
		`id="tab-client"`,
		`id="tab-dot1x"`,
		`id="tab-code"`,
		`name="cert_type" value="server"`,
		`name="cert_type" value="client"`,
		`name="cert_type" value="dot1x"`,
		`name="cert_type" value="codeSigning"`,
		`data-type="server"`,
		`data-type="client"`,
		`data-type="dot1x"`,
		`data-type="codeSigning"`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("index page missing marker %q", marker)
		}
	}
}

func TestIndexRendersNoTabsBeforeCA(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	tr, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	a.Translations = tr
	if err := os.MkdirAll(filepath.Join(a.DataDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handleIndex(a, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleIndex status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `class="tabs js-tabs"`) {
		t.Fatal("index should not render tabs before a CA exists")
	}
}
