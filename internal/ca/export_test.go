package ca

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// helper to read a single archive entry's bytes from a tar.gz.
func readArchiveEntry(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader() error = %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("archive entry %s not found: %v", name, err)
		}
		if hdr.Name == name {
			buf := make([]byte, hdr.Size)
			if _, err := io.ReadFull(tr, buf); err != nil {
				t.Fatalf("read %s error = %v", name, err)
			}
			return buf
		}
	}
}

func TestWriteCertificateArchiveChainMatchesSigner(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	// Root-signed leaf, created BEFORE the intermediate exists.
	if err := a.CreateServerCert("root-signed.local", []string{"root-signed.local"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("CreateServerCert() error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cert, got %d (err=%v)", len(certs), err)
	}
	certID := certs[0].ID

	// Now an intermediate exists too. Exporting the root-signed leaf must NOT
	// pull the intermediate into the issuer chain.
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	certDir := filepath.Join(a.DataDir, "certs", certID)
	rec := httptest.NewRecorder()
	if err := WriteCertificateArchive(rec, certDir, certID, a.DataDir, ""); err != nil {
		t.Fatalf("WriteCertificateArchive() error = %v", err)
	}

	issuerChain := readArchiveEntry(t, rec.Body.Bytes(), "issuer-chain.pem")
	blocks := decodeAllPEMBlocks(t, issuerChain)
	if len(blocks) != 1 {
		t.Fatalf("issuer-chain.pem blocks = %d, want 1 (root only for a root-signed cert)", len(blocks))
	}

	// The intermediate-signed case must include both the intermediate and root.
	if err := a.CreateServerCert("intermediate-signed.local", []string{"intermediate-signed.local"}, 1, "", "", true, "server"); err != nil {
		t.Fatalf("CreateServerCert(intermediate) error = %v", err)
	}
	allCerts, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	intID := ""
	for _, c := range allCerts {
		if c.CommonName == "intermediate-signed.local" {
			intID = c.ID
		}
	}
	if intID == "" {
		t.Fatal("intermediate-signed cert not found")
	}
	rec2 := httptest.NewRecorder()
	if err := WriteCertificateArchive(rec2, filepath.Join(a.DataDir, "certs", intID), intID, a.DataDir, ""); err != nil {
		t.Fatalf("WriteCertificateArchive(intermediate) error = %v", err)
	}
	issuerChain2 := readArchiveEntry(t, rec2.Body.Bytes(), "issuer-chain.pem")
	if got := len(decodeAllPEMBlocks(t, issuerChain2)); got != 2 {
		t.Fatalf("intermediate-signed issuer-chain.pem blocks = %d, want 2", got)
	}

	// chain.pem must be cert + issuer-chain for both cases.
	chain := readArchiveEntry(t, rec.Body.Bytes(), "chain.pem")
	if got := len(decodeAllPEMBlocks(t, chain)); got != 2 {
		t.Fatalf("root-signed chain.pem blocks = %d, want 2 (leaf + root)", got)
	}
}

func decodeAllPEMBlocks(t *testing.T, data []byte) []*pem.Block {
	t.Helper()
	var blocks []*pem.Block
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		t.Fatalf("no PEM blocks found in archive entry")
	}
	return blocks
}
