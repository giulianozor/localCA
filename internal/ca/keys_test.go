package ca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	initial := []byte("first")
	if err := atomicWriteFile(path, initial, 0o600); err != nil {
		t.Fatalf("atomicWriteFile(initial) error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}
	if string(got) != string(initial) {
		t.Fatalf("got %q, want %q", got, initial)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}

	replacement := []byte("second-and-longer")
	if err := atomicWriteFile(path, replacement, 0o600); err != nil {
		t.Fatalf("atomicWriteFile(replacement) error = %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}
	if string(got) != string(replacement) {
		t.Fatalf("got %q, want %q", got, replacement)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir error = %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}
