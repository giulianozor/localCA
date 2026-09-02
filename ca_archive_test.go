package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestCA creates an app with a CA and one issued certificate so we can
// exercise whole-CA archive round-trips.
func buildTestCA(t *testing.T) (*app, string) {
	t.Helper()
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("myserver.example.com", []string{
		"myserver.example.com", "127.0.0.1",
	}, 1, "", "", false); err != nil {
		t.Fatalf("createServerCert() error = %v", err)
	}
	certs, err := a.listCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	return a, certs[0].ID
}

func TestCAArchiveRoundTripPlain(t *testing.T) {
	src, _ := buildTestCA(t)

	raw, err := src.buildCAArchive()
	if err != nil {
		t.Fatalf("buildCAArchive() error = %v", err)
	}
	if bytes.Contains(raw, []byte(caArchiveMagic)) {
		t.Fatal("plain archive unexpectedly contained magic marker")
	}

	dst := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := dst.importCAArchive(bytes.NewReader(raw), ""); err != nil {
		t.Fatalf("importCAArchive() error = %v", err)
	}

	assertCAEqual(t, src, dst)
}

func TestCAArchiveRoundTripEncrypted(t *testing.T) {
	src, _ := buildTestCA(t)

	raw, err := src.buildCAArchive()
	if err != nil {
		t.Fatalf("buildCAArchive() error = %v", err)
	}
	enc, err := encryptCAArchive(raw, "s3cret")
	if err != nil {
		t.Fatalf("encryptCAArchive() error = %v", err)
	}
	if !bytes.HasPrefix(enc, []byte(caArchiveMagic)) {
		t.Fatal("encrypted archive missing magic marker")
	}

	// Decrypt/import with correct passphrase.
	dst := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := dst.importCAArchive(bytes.NewReader(enc), "s3cret"); err != nil {
		t.Fatalf("importCAArchive() with correct passphrase error = %v", err)
	}
	assertCAEqual(t, src, dst)

	// Wrong passphrase must fail.
	dst2 := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := dst2.importCAArchive(bytes.NewReader(enc), "wrong"); err == nil {
		t.Fatal("import with wrong passphrase succeeded, want error")
	}
	// Nothing should have been restored after a failed import.
	if _, err := os.Stat(filepath.Join(dst2.dataDir, "ca-key.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed import left files behind (err=%v)", err)
	}
}

func TestCAImportRefusesWhenCAExists(t *testing.T) {
	src, _ := buildTestCA(t)
	raw, err := src.buildCAArchive()
	if err != nil {
		t.Fatalf("buildCAArchive() error = %v", err)
	}

	dst, _ := buildTestCA(t) // already has a CA
	if err := dst.importCAArchive(bytes.NewReader(raw), ""); err == nil {
		t.Fatal("import into existing CA succeeded, want error")
	}
}

func TestCAImportRejectsTraversal(t *testing.T) {
	dst := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if _, err := safeArchivePath(dst.dataDir, "../../../etc/passwd"); err == nil {
		t.Fatal("safeArchivePath accepted traversal path")
	}
	if _, err := safeArchivePath(dst.dataDir, "/etc/passwd"); err == nil {
		t.Fatal("safeArchivePath accepted absolute path")
	}
	if _, err := safeArchivePath(dst.dataDir, "certs/x/cert.pem"); err != nil {
		t.Fatalf("safeArchivePath rejected valid relative path: %v", err)
	}
}

func TestCAImportValidatesKeyMatch(t *testing.T) {
	src, certID := buildTestCA(t)
	raw, err := src.buildCAArchive()
	if err != nil {
		t.Fatalf("buildCAArchive() error = %v", err)
	}

	// Corrupt the CA key while leaving the cert intact, then import.
	// We tamper with the exported archive's ca-key.pem bytes directly.
	tampered := tamperTarEntry(t, raw, "ca-key.pem", []byte("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n"))

	dst := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := dst.importCAArchive(bytes.NewReader(tampered), ""); err == nil {
		t.Fatal("import with mismatched CA key succeeded, want error")
	}
	_ = certID
}

func assertCAEqual(t *testing.T, src, dst *app) {
	t.Helper()
	for _, name := range caArchiveFiles() {
		srcData, err := os.ReadFile(filepath.Join(src.dataDir, name))
		srcMissing := errors.Is(err, os.ErrNotExist)
		if err != nil && !srcMissing {
			t.Fatalf("read src %s: %v", name, err)
		}
		dstData, err := os.ReadFile(filepath.Join(dst.dataDir, name))
		dstMissing := errors.Is(err, os.ErrNotExist)
		if err != nil && !dstMissing {
			t.Fatalf("read dst %s: %v", name, err)
		}
		if srcMissing != dstMissing {
			t.Fatalf("%s existence mismatch: src=%v dst=%v", name, srcMissing, dstMissing)
		}
		if !bytes.Equal(srcData, dstData) {
			t.Fatalf("%s content mismatch", name)
		}
	}

	// Compare issued certificates.
	srcCerts, err := src.listCerts()
	if err != nil {
		t.Fatalf("src listCerts: %v", err)
	}
	dstCerts, err := dst.listCerts()
	if err != nil {
		t.Fatalf("dst listCerts: %v", err)
	}
	if len(srcCerts) != len(dstCerts) {
		t.Fatalf("cert count mismatch: src=%d dst=%d", len(srcCerts), len(dstCerts))
	}
	for i := range srcCerts {
		if srcCerts[i].ID != dstCerts[i].ID {
			t.Fatalf("cert ID mismatch: %s vs %s", srcCerts[i].ID, dstCerts[i].ID)
		}
		for _, f := range []string{"cert.pem", "key.pem", "csr.pem", "metadata.json"} {
			s := filepath.Join(src.dataDir, "certs", srcCerts[i].ID, f)
			d := filepath.Join(dst.dataDir, "certs", dstCerts[i].ID, f)
			sd, err := os.ReadFile(s)
			if err != nil {
				t.Fatalf("read %s: %v", s, err)
			}
			dd, err := os.ReadFile(d)
			if err != nil {
				t.Fatalf("read %s: %v", d, err)
			}
			if !bytes.Equal(sd, dd) {
				t.Fatalf("%s/%s content mismatch", srcCerts[i].ID, f)
			}
		}
	}
}

// tamperTarEntry rewrites a specific top-level tar entry's content.
func tamperTarEntry(t *testing.T, archive []byte, target string, newContent []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var rebuilt bytes.Buffer
	gw := gzip.NewWriter(&rebuilt)
	tw := tar.NewWriter(gw)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		content := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, content); err != nil {
			t.Fatalf("io.ReadFull: %v", err)
		}
		if !found && hdr.Name == target {
			content = newContent
			found = true
		}
		hdr.Size = int64(len(content))
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tw.WriteHeader: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("tw.Write: %v", err)
		}
	}
	if !found {
		t.Fatalf("target %s not found in archive", target)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gw.Close: %v", err)
	}
	return rebuilt.Bytes()
}

func TestHandleDownloadCAArchive(t *testing.T) {
	a, _ := buildTestCA(t)

	req := httptest.NewRequest(http.MethodGet, "/download?kind=ca-all-tar-gz&export_passphrase=backup-pass", nil)
	rr := httptest.NewRecorder()
	a.handleDownload(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handleDownload(ca-all-tar-gz) status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.Bytes()
	if !bytes.HasPrefix(body, []byte(caArchiveMagic)) {
		t.Fatal("exported CA archive was not encrypted despite passphrase")
	}

	// Download without passphrase should produce a plain tar.gz.
	req2 := httptest.NewRequest(http.MethodGet, "/download?kind=ca-all-tar-gz", nil)
	rr2 := httptest.NewRecorder()
	a.handleDownload(rr2, req2)
	if bytes.HasPrefix(rr2.Body.Bytes(), []byte(caArchiveMagic)) {
		t.Fatal("exported CA archive unexpectedly encrypted without passphrase")
	}
}

func TestHandleImportCA(t *testing.T) {
	src, certID := buildTestCA(t)
	raw, err := src.buildCAArchive()
	if err != nil {
		t.Fatalf("buildCAArchive() error = %v", err)
	}

	dst := &app{dataDir: t.TempDir(), defaultLang: "en"}

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
	dst.handleImportCA(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("handleImportCA status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if got := rr.Header().Get("Location"); !strings.Contains(got, "msg=") {
		t.Fatalf("expected success redirect, got %q", got)
	}
	if _, err := os.Stat(filepath.Join(dst.dataDir, "certs", certID, "cert.pem")); err != nil {
		t.Fatalf("issued cert not restored after import: %v", err)
	}
}
