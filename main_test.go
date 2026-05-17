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
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseValidityYears(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{name: "default", input: "", want: defaultCertValidityYears},
		{name: "valid", input: "30", want: 30},
		{name: "too high", input: "31", wantErr: true},
		{name: "invalid", input: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseValidityYears(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseValidityYears() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseValidityYears() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSANs(t *testing.T) {
	t.Run("valid and deduplicated", func(t *testing.T) {
		got, err := parseSANs("Dev.Local, 127.0.0.1, dev.local, api.locsl")
		if err != nil {
			t.Fatalf("parseSANs() error = %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("parseSANs() len = %d, want 3", len(got))
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := parseSANs("   ,   "); err == nil {
			t.Fatal("parseSANs() expected error")
		}
	})
}

func TestResolveCertificateDir(t *testing.T) {
	tempDir := t.TempDir()
	a := &app{dataDir: tempDir}
	if err := os.MkdirAll(filepath.Join(tempDir, "certs", "cert-1"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	gotPath, gotID, err := a.resolveCertificateDir("cert-1")
	if err != nil {
		t.Fatalf("resolveCertificateDir() error = %v", err)
	}
	if gotID != "cert-1" {
		t.Fatalf("resolveCertificateDir() id = %s, want cert-1", gotID)
	}
	wantPath := filepath.Join(tempDir, "certs", "cert-1")
	if gotPath != wantPath {
		t.Fatalf("resolveCertificateDir() path = %s, want %s", gotPath, wantPath)
	}

	if _, _, err := a.resolveCertificateDir("../cert-1"); err == nil {
		t.Fatal("resolveCertificateDir() expected error for invalid id")
	}
}

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

func TestLoadTranslationsUsesEmbeddedAssets(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir(%s) error = %v", tempDir, err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	translations, err := loadTranslations()
	if err != nil {
		t.Fatalf("loadTranslations() error = %v", err)
	}
	if got := translations["en"]["language.label"]; got != "Select language" {
		t.Fatalf("translations[en][language.label] = %q, want %q", got, "Select language")
	}
	if got := translations["ja"]["cert.create.button"]; got != "証明書を作成" {
		t.Fatalf("translations[ja][cert.create.button] = %q, want %q", got, "証明書を作成")
	}
}

func TestFilterCertificates(t *testing.T) {
	certs := []certMetadata{
		{ID: "cert-1", CommonName: "dev.local", SANs: []string{"dev.local", "127.0.0.1"}, CreatedAt: time.Now()},
		{ID: "cert-2", CommonName: "api.locsl", SANs: []string{"api.locsl"}, CreatedAt: time.Now()},
	}

	t.Run("empty query returns all", func(t *testing.T) {
		got := filterCertificates(certs, "")
		if !reflect.DeepEqual(got, certs) {
			t.Fatalf("filterCertificates() = %#v, want %#v", got, certs)
		}
	})

	t.Run("filter by common name", func(t *testing.T) {
		got := filterCertificates(certs, "api")
		if len(got) != 1 || got[0].ID != "cert-2" {
			t.Fatalf("filterCertificates() got %#v, want cert-2 only", got)
		}
	})

	t.Run("filter by SAN case insensitive", func(t *testing.T) {
		got := filterCertificates(certs, "DEV.LOCAL")
		if len(got) != 1 || got[0].ID != "cert-1" {
			t.Fatalf("filterCertificates() got %#v, want cert-1 only", got)
		}
	})
}

func TestCreateServerCertSavesCSRAndSeparatesIPSANs(t *testing.T) {
	a, certID := createTestCertificate(t)
	certDir := filepath.Join(a.dataDir, "certs", certID)

	cert := parseCertificatePEM(t, filepath.Join(certDir, "cert.pem"))
	if !reflect.DeepEqual(cert.DNSNames, []string{"myserver.example.com", "myserver.internal"}) {
		t.Fatalf("certificate DNSNames = %#v, want %#v", cert.DNSNames, []string{"myserver.example.com", "myserver.internal"})
	}
	assertIPAddresses(t, cert.IPAddresses, []string{"192.168.1.100", "10.0.0.50", "127.0.0.1"})

	csrPEM, err := os.ReadFile(filepath.Join(certDir, "csr.pem"))
	if err != nil {
		t.Fatalf("read csr.pem: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("csr.pem did not contain a PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest() error = %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature() error = %v", err)
	}
	if !reflect.DeepEqual(csr.DNSNames, []string{"myserver.example.com", "myserver.internal"}) {
		t.Fatalf("CSR DNSNames = %#v, want %#v", csr.DNSNames, []string{"myserver.example.com", "myserver.internal"})
	}
	assertIPAddresses(t, csr.IPAddresses, []string{"192.168.1.100", "10.0.0.50", "127.0.0.1"})
}

func TestHandleDownloadSupportsCSRAndArchive(t *testing.T) {
	a, certID := createTestCertificate(t)

	t.Run("csr pem", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/download?kind=csr-pem&id="+certID, nil)
		rr := httptest.NewRecorder()

		a.handleDownload(rr, req)

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

		a.handleDownload(rr, req)

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

func TestCreateServerCertUsesIntermediateAsIssuer(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("createIntermediateCA() error = %v", err)
	}
	if err := a.createServerCert("leaf.local", []string{"leaf.local"}, 1, "", ""); err != nil {
		t.Fatalf("createServerCert() error = %v", err)
	}
	certs, err := a.listCerts()
	if err != nil {
		t.Fatalf("listCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("listCerts() len = %d, want 1", len(certs))
	}
	cert := parseCertificatePEM(t, filepath.Join(tempDir, "certs", certs[0].ID, "cert.pem"))
	intermediate := parseCertificatePEM(t, filepath.Join(tempDir, "intermediate-cert.pem"))
	if cert.Issuer.CommonName != intermediate.Subject.CommonName {
		t.Fatalf("leaf issuer CN = %q, want %q", cert.Issuer.CommonName, intermediate.Subject.CommonName)
	}
}

func TestCreateServerCertRequiresSignerPassphrase(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", "root-pass"); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("leaf.local", []string{"leaf.local"}, 1, "", ""); err == nil {
		t.Fatal("createServerCert() expected error when signer passphrase is missing")
	}
	if err := a.createServerCert("leaf.local", []string{"leaf.local"}, 1, "", "root-pass"); err != nil {
		t.Fatalf("createServerCert() with signer passphrase error = %v", err)
	}
}

func TestCreateIntermediateCAUsesDefaultValidityYears(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("createIntermediateCA() error = %v", err)
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !has {
		t.Fatal("loadConfig() expected config to exist")
	}
	if cfg.IntermediateValidityYears != intermediateYears {
		t.Fatalf("IntermediateValidityYears = %d, want %d", cfg.IntermediateValidityYears, intermediateYears)
	}
}

func TestChangeCAPassphraseSetAndRemove(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", "initial-pass"); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.changeCAPassphrase("initial-pass", "new-pass"); err != nil {
		t.Fatalf("changeCAPassphrase(set) error = %v", err)
	}
	if err := a.createServerCert("with-new-pass.local", []string{"with-new-pass.local"}, 1, "", "new-pass"); err != nil {
		t.Fatalf("createServerCert() with new signer passphrase error = %v", err)
	}
	if err := a.changeCAPassphrase("new-pass", ""); err != nil {
		t.Fatalf("changeCAPassphrase(remove) error = %v", err)
	}
	if err := a.createServerCert("without-pass.local", []string{"without-pass.local"}, 1, "", ""); err != nil {
		t.Fatalf("createServerCert() without signer passphrase error = %v", err)
	}
}

func TestRevokeAndRenewCertificate(t *testing.T) {
	a, certID := createTestCertificate(t)
	revokeForm := url.Values{}
	revokeForm.Set("id", certID)
	revokeReq := httptest.NewRequest(http.MethodPost, "/certs/revoke", strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRR := httptest.NewRecorder()
	a.handleRevokeCert(revokeRR, revokeReq)
	if revokeRR.Code != http.StatusSeeOther {
		t.Fatalf("handleRevokeCert() status = %d, want %d", revokeRR.Code, http.StatusSeeOther)
	}
	certDir := filepath.Join(a.dataDir, "certs", certID)
	meta, err := a.loadCertMetadata(certDir)
	if err != nil {
		t.Fatalf("loadCertMetadata() error = %v", err)
	}
	if meta.RevokedAt == nil {
		t.Fatal("expected certificate to be revoked")
	}

	renewForm := url.Values{}
	renewForm.Set("id", certID)
	renewReq := httptest.NewRequest(http.MethodPost, "/certs/renew", strings.NewReader(renewForm.Encode()))
	renewReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	renewRR := httptest.NewRecorder()
	a.handleRenewCert(renewRR, renewReq)
	if renewRR.Code != http.StatusSeeOther {
		t.Fatalf("handleRenewCert() status = %d, want %d", renewRR.Code, http.StatusSeeOther)
	}
	certs, err := a.listCerts()
	if err != nil {
		t.Fatalf("listCerts() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("listCerts() len = %d, want 2 after renewal", len(certs))
	}
}

func TestHandleDownloadArchiveRejectsExportPassphraseForEncryptedKey(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("leaf.local", []string{"leaf.local"}, 1, "leaf-pass", ""); err != nil {
		t.Fatalf("createServerCert() error = %v", err)
	}
	certs, err := a.listCerts()
	if err != nil {
		t.Fatalf("listCerts() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/download?kind=all-tar-gz&id="+certs[0].ID+"&export_passphrase=export-pass", nil)
	rr := httptest.NewRecorder()
	a.handleDownload(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("handleDownload() status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func createTestCertificate(t *testing.T) (*app, string) {
	t.Helper()

	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("myserver.example.com", []string{
		"myserver.example.com",
		"myserver.internal",
		"192.168.1.100",
		"10.0.0.50",
		"127.0.0.1",
	}, 1, "", ""); err != nil {
		t.Fatalf("createServerCert() error = %v", err)
	}
	certs, err := a.listCerts()
	if err != nil {
		t.Fatalf("listCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("listCerts() len = %d, want 1", len(certs))
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

func TestGenerateCRL(t *testing.T) {
	translations, err := loadTranslations()
	if err != nil {
		t.Fatalf("loadTranslations() error = %v", err)
	}
	a, certID := createTestCertificate(t)
	a.translations = translations

	// Revoke the certificate
	now := time.Now()
	certDir := filepath.Join(a.dataDir, "certs", certID)
	meta, err := a.loadCertMetadata(certDir)
	if err != nil {
		t.Fatalf("loadCertMetadata() error = %v", err)
	}
	meta.RevokedAt = &now
	if err := a.saveCertMetadata(certDir, meta); err != nil {
		t.Fatalf("saveCertMetadata() error = %v", err)
	}

	// Generate CRL
	if err := a.generateCRL("en", ""); err != nil {
		t.Fatalf("generateCRL() error = %v", err)
	}

	// Verify crl.pem exists and is parseable
	crlPEM, err := os.ReadFile(filepath.Join(a.dataDir, "crl.pem"))
	if err != nil {
		t.Fatalf("read crl.pem error = %v", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("crl.pem has no PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList() error = %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL entries = %d, want 1", len(crl.RevokedCertificateEntries))
	}

	// Verify crl.der exists
	crlDER, err := os.ReadFile(filepath.Join(a.dataDir, "crl.der"))
	if err != nil {
		t.Fatalf("read crl.der error = %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("crl.der is empty")
	}

	// Verify the serial in the CRL matches the revoked cert
	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		t.Fatalf("read cert.pem error = %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("cert.pem has no PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("CRL entry serial = %s, want %s",
			crl.RevokedCertificateEntries[0].SerialNumber,
			cert.SerialNumber)
	}
}

func TestHandleGenerateCRL(t *testing.T) {
	translations, err := loadTranslations()
	if err != nil {
		t.Fatalf("loadTranslations() error = %v", err)
	}
	a, certID := createTestCertificate(t)
	a.translations = translations

	// Revoke via handler
	revokeForm := url.Values{}
	revokeForm.Set("id", certID)
	revokeReq := httptest.NewRequest(http.MethodPost, "/certs/revoke", strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRR := httptest.NewRecorder()
	a.handleRevokeCert(revokeRR, revokeReq)
	if revokeRR.Code != http.StatusSeeOther {
		t.Fatalf("handleRevokeCert() status = %d, want %d", revokeRR.Code, http.StatusSeeOther)
	}

	// Generate CRL via handler
	genReq := httptest.NewRequest(http.MethodPost, "/certs/crl/generate", strings.NewReader(""))
	genReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	genRR := httptest.NewRecorder()
	a.handleGenerateCRL(genRR, genReq)
	if genRR.Code != http.StatusSeeOther {
		t.Fatalf("handleGenerateCRL() status = %d, want %d", genRR.Code, http.StatusSeeOther)
	}
	if !strings.Contains(genRR.Header().Get("Location"), "msg=") {
		t.Fatalf("handleGenerateCRL() expected success redirect, got %s", genRR.Header().Get("Location"))
	}

	// Verify CRL file was created
	if _, err := os.Stat(filepath.Join(a.dataDir, "crl.pem")); err != nil {
		t.Fatalf("crl.pem not created: %v", err)
	}

	// Download CRL via handler
	dlReq := httptest.NewRequest(http.MethodGet, "/download?kind=crl-pem", nil)
	dlRR := httptest.NewRecorder()
	a.handleDownload(dlRR, dlReq)
	if dlRR.Code != http.StatusOK {
		t.Fatalf("handleDownload(crl-pem) status = %d, want %d", dlRR.Code, http.StatusOK)
	}
	if dlRR.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("handleDownload(crl-pem) Content-Type = %s", dlRR.Header().Get("Content-Type"))
	}
}
