package ca

import (
	"encoding/json"
	"os"
	"path/filepath"
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
