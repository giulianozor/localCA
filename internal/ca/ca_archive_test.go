package ca

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// buildTestCA creates an app with a CA and one issued certificate so we can
// exercise whole-CA archive round-trips.
func buildTestCA(t *testing.T) (*App, string) {
	t.Helper()
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
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

func TestCAArchiveRoundTripPlain(t *testing.T) {
	src, _ := buildTestCA(t)

	raw, err := src.BuildCAArchive()
	if err != nil {
		t.Fatalf("BuildCAArchive() error = %v", err)
	}
	if bytes.Contains(raw, []byte(CAArchiveMagic)) {
		t.Fatal("plain archive unexpectedly contained magic marker")
	}

	dst := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := dst.ImportCAArchive(bytes.NewReader(raw), ""); err != nil {
		t.Fatalf("ImportCAArchive() error = %v", err)
	}

	assertCAEqual(t, src, dst)
}

func TestCAArchiveRoundTripEncrypted(t *testing.T) {
	src, _ := buildTestCA(t)

	raw, err := src.BuildCAArchive()
	if err != nil {
		t.Fatalf("BuildCAArchive() error = %v", err)
	}
	enc, err := EncryptCAArchive(raw, "s3cret")
	if err != nil {
		t.Fatalf("EncryptCAArchive() error = %v", err)
	}
	if !bytes.HasPrefix(enc, []byte(CAArchiveMagic)) {
		t.Fatal("encrypted archive missing magic marker")
	}

	// Decrypt/import with correct passphrase.
	dst := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := dst.ImportCAArchive(bytes.NewReader(enc), "s3cret"); err != nil {
		t.Fatalf("ImportCAArchive() with correct passphrase error = %v", err)
	}
	assertCAEqual(t, src, dst)

	// Wrong passphrase must fail.
	dst2 := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := dst2.ImportCAArchive(bytes.NewReader(enc), "wrong"); err == nil {
		t.Fatal("import with wrong passphrase succeeded, want error")
	}
	// Nothing should have been restored after a failed import.
	if _, err := os.Stat(filepath.Join(dst2.DataDir, "ca-key.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed import left files behind (err=%v)", err)
	}
}

func TestCAImportRefusesWhenCAExists(t *testing.T) {
	src, _ := buildTestCA(t)
	raw, err := src.BuildCAArchive()
	if err != nil {
		t.Fatalf("BuildCAArchive() error = %v", err)
	}

	dst, _ := buildTestCA(t) // already has a CA
	if err := dst.ImportCAArchive(bytes.NewReader(raw), ""); err == nil {
		t.Fatal("import into existing CA succeeded, want error")
	}
}

func TestCAImportRejectsTraversal(t *testing.T) {
	dst := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if _, err := SafeArchivePath(dst.DataDir, "../../../etc/passwd"); err == nil {
		t.Fatal("SafeArchivePath accepted traversal path")
	}
	if _, err := SafeArchivePath(dst.DataDir, "/etc/passwd"); err == nil {
		t.Fatal("SafeArchivePath accepted absolute path")
	}
	if _, err := SafeArchivePath(dst.DataDir, "certs/x/cert.pem"); err != nil {
		t.Fatalf("SafeArchivePath rejected valid relative path: %v", err)
	}
}

func TestCAImportValidatesKeyMatch(t *testing.T) {
	src, _ := buildTestCA(t)
	raw, err := src.BuildCAArchive()
	if err != nil {
		t.Fatalf("BuildCAArchive() error = %v", err)
	}

	// Corrupt the CA key while leaving the cert intact, then import.
	// We tamper with the exported archive's ca-key.pem bytes directly.
	tampered := tamperTarEntry(t, raw, "ca-key.pem", []byte("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n"))

	dst := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := dst.ImportCAArchive(bytes.NewReader(tampered), ""); err == nil {
		t.Fatal("import with mismatched CA key succeeded, want error")
	}
}

func assertCAEqual(t *testing.T, src, dst *App) {
	t.Helper()
	for _, name := range CAArchiveFiles() {
		srcData, err := os.ReadFile(filepath.Join(src.DataDir, name))
		srcMissing := errors.Is(err, os.ErrNotExist)
		if err != nil && !srcMissing {
			t.Fatalf("read src %s: %v", name, err)
		}
		dstData, err := os.ReadFile(filepath.Join(dst.DataDir, name))
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
	srcCerts, err := src.ListCerts()
	if err != nil {
		t.Fatalf("src ListCerts: %v", err)
	}
	dstCerts, err := dst.ListCerts()
	if err != nil {
		t.Fatalf("dst ListCerts: %v", err)
	}
	if len(srcCerts) != len(dstCerts) {
		t.Fatalf("cert count mismatch: src=%d dst=%d", len(srcCerts), len(dstCerts))
	}
	for i := range srcCerts {
		if srcCerts[i].ID != dstCerts[i].ID {
			t.Fatalf("cert ID mismatch: %s vs %s", srcCerts[i].ID, dstCerts[i].ID)
		}
		for _, f := range []string{"cert.pem", "key.pem", "csr.pem", "metadata.json"} {
			s := filepath.Join(src.DataDir, "certs", srcCerts[i].ID, f)
			d := filepath.Join(dst.DataDir, "certs", dstCerts[i].ID, f)
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
