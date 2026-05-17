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
		{name: "default", input: "", want: 1},
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

		for _, name := range []string{"cert.der", "cert.pem", "chain.pem", "csr.pem", "key.der", "key.pem", "key-pkcs8.pem", "metadata.json"} {
			if !names[name] {
				t.Fatalf("archive missing %s; got %#v", name, names)
			}
		}
	})
}

func createTestCertificate(t *testing.T) (*app, string) {
	t.Helper()

	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &app{dataDir: tempDir, defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT"); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("myserver.example.com", []string{
		"myserver.example.com",
		"myserver.internal",
		"192.168.1.100",
		"10.0.0.50",
		"127.0.0.1",
	}, 1); err != nil {
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
