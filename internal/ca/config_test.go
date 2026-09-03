package ca

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListCertsNormalizesLegacyMetadataType(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	certDir := filepath.Join(a.DataDir, "certs", "cert-123")
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}

	legacy := map[string]interface{}{
		"id":             "cert-123",
		"common_name":    "legacy-client@example.com",
		"client":         true,
		"validity_years": 1,
		"created_at":     "2020-01-01T00:00:00Z",
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "metadata.json"), raw, 0o640); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("ListCerts() len = %d, want 1", len(certs))
	}
	if got := certs[0].Type; got != "client" {
		t.Fatalf("ListCerts() normalized Type = %q, want %q (legacy metadata should map client->client)", got, "client")
	}
}

func TestSaveConfigAtomicRoundTrip(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "it"}
	cfg := Config{Organization: "ACME", Country: "US", CAPassphraseSet: true, Language: "it"}
	if err := a.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	got, has, err := a.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if !has {
		t.Fatal("LoadConfig() has = false, want true")
	}
	if got.Organization != "ACME" || got.Country != "US" || !got.CAPassphraseSet || got.Language != "it" {
		t.Fatalf("LoadConfig() got %+v, want round-trip of %+v", got, cfg)
	}

	entries, err := os.ReadDir(a.DataDir)
	if err != nil {
		t.Fatalf("ReadDir error = %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file after SaveConfig: %s", e.Name())
		}
	}
}

func TestSaveCertMetadataAtomicNoExecutionBit(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	certDir := filepath.Join(a.DataDir, "certs", "cert-1")
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	meta := CertMetadata{ID: "cert-1", CommonName: "a.example", Type: "server", Signer: "ca", ValidityYears: 1}
	if err := a.SaveCertMetadata(certDir, meta); err != nil {
		t.Fatalf("SaveCertMetadata() error = %v", err)
	}

	got, err := a.LoadCertMetadata(certDir)
	if err != nil {
		t.Fatalf("LoadCertMetadata() error = %v", err)
	}
	if got.Signer != "ca" || got.Type != "server" || got.CommonName != "a.example" {
		t.Fatalf("LoadCertMetadata() got %+v, want round-trip of %+v", got, meta)
	}

	info, err := os.Stat(filepath.Join(certDir, "metadata.json"))
	if err != nil {
		t.Fatalf("Stat error = %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("metadata.json mode = %v, want 0640", info.Mode().Perm())
	}
	entries, err := os.ReadDir(certDir)
	if err != nil {
		t.Fatalf("ReadDir error = %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file after SaveCertMetadata: %s", e.Name())
		}
	}
}
