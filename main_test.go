package main

import (
	"os"
	"path/filepath"
	"testing"
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
