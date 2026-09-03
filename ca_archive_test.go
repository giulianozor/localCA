package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giulianozor/localCA/internal/ca"
)

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
