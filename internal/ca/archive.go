package ca

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// CAArchiveFiles returns the explicit list of top-level files that make up a
// whole-CA archive, in a deterministic order.
func CAArchiveFiles() []string {
	return []string{
		"config.json",
		"ca-cert.pem",
		"ca-cert.der",
		"ca-key.pem",
		"intermediate-cert.pem",
		"intermediate-key.pem",
		"intermediate-chain.pem",
		"crl.pem",
		"crl.der",
	}
}

// BuildCAArchive builds a tar.gz of the whole CA state (top-level files plus
// the issued certs/ tree) and returns the archived bytes.
func (a *App) BuildCAArchive() ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, name := range CAArchiveFiles() {
		content, err := os.ReadFile(filepath.Join(a.DataDir, name))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if err := AppendTarFile(tw, name, content, 0o640); err != nil {
			return nil, err
		}
	}

	entries, err := os.ReadDir(filepath.Join(a.DataDir, "certs"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No issued certificates yet (e.g. a root CA with no leaves).
			entries = nil
		} else {
			return nil, err
		}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subDir := filepath.Join(a.DataDir, "certs", e.Name())
		files, err := os.ReadDir(subDir)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			content, err := os.ReadFile(filepath.Join(subDir, f.Name()))
			if err != nil {
				return nil, err
			}
			name := filepath.ToSlash(filepath.Join("certs", e.Name(), f.Name()))
			mode := os.FileMode(0o640)
			if strings.HasSuffix(f.Name(), ".pem") && strings.Contains(f.Name(), "key") {
				mode = 0o600
			}
			if err := AppendTarFile(tw, name, content, mode); err != nil {
				return nil, err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func AppendTarFile(tw *tar.Writer, name string, content []byte, mode os.FileMode) error {
	hdr := &tar.Header{
		Name: name,
		Mode: int64(mode),
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}

// SafeArchivePath validates a tar entry name and returns the corresponding
// path under base, rejecting traversal and absolute paths.
func SafeArchivePath(base, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty path in archive")
	}
	clean := filepath.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
		return "", errors.New("invalid path in archive")
	}
	full := filepath.Join(base, clean)
	if !strings.HasPrefix(full, filepath.Clean(base)+string(filepath.Separator)) {
		return "", errors.New("invalid path in archive")
	}
	return full, nil
}

// WriteCAArchive streams a whole-CA archive to the response with optional
// passphrase encryption.
func (a *App) WriteCAArchive(w http.ResponseWriter, exportPassphrase string) error {
	raw, err := a.BuildCAArchive()
	if err != nil {
		return err
	}
	payload := raw
	if exportPassphrase != "" {
		payload, err = EncryptCAArchive(raw, exportPassphrase)
		if err != nil {
			return err
		}
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"localca-ca-backup.tar.gz\"")
	_, err = w.Write(payload)
	return err
}

// ImportCAArchive restores a whole-CA archive (plain tar.gz or encrypted) into
// the data directory. It refuses to run when a CA already exists.
func (a *App) ImportCAArchive(r io.Reader, importPassphrase string) error {
	if _, hasCA, err := a.LoadConfig(); err != nil {
		return err
	} else if hasCA {
		return errors.New("a CA already exists: restore into an empty data directory")
	}

	limited := io.LimitReader(r, MaxImportArchive)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) >= MaxImportArchive {
		return errors.New("imported archive is too large")
	}

	payload, encrypted, err := DecryptCAArchive(data, importPassphrase)
	if err != nil {
		return err
	}
	if encrypted {
		data = payload
	}

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	restored := map[string]bool{}
	type fileEntry struct {
		path string
		mode os.FileMode
		data []byte
	}
	var files []fileEntry
	var dirs []string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("corrupted CA archive: " + err.Error())
		}
		full, err := SafeArchivePath(a.DataDir, hdr.Name)
		if err != nil {
			return err
		}
		dir := filepath.Dir(full)
		if strings.HasPrefix(full, filepath.Join(a.DataDir, "certs")) && !strings.HasSuffix(hdr.Name, "/") {
			dirs = append(dirs, dir)
		}
		if strings.HasSuffix(hdr.Name, "/") {
			continue
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return errors.New("corrupted CA archive: " + err.Error())
		}
		restored[hdr.Name] = true
		files = append(files, fileEntry{path: full, mode: os.FileMode(hdr.Mode) & 0o777, data: buf})
	}

	if !restored["config.json"] || !restored["ca-cert.pem"] || !restored["ca-key.pem"] {
		return errors.New("imported archive is missing required CA files (config.json, ca-cert.pem, ca-key.pem)")
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	written := make([]string, 0, len(files))
	for _, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0o640
		}
		if strings.Contains(filepath.Base(f.path), "key") && strings.HasSuffix(f.path, ".pem") {
			mode = 0o600
		}
		if err := os.WriteFile(f.path, f.data, mode); err != nil {
			return err
		}
		written = append(written, f.path)
	}

	cleanup := func() {
		for _, p := range written {
			_ = os.Remove(p)
		}
		for _, d := range dirs {
			_ = os.Remove(d) // only removes now-empty directories
		}
	}

	_, has, err := a.LoadConfig()
	if err != nil {
		cleanup()
		return err
	}
	if !has {
		cleanup()
		return errors.New("imported archive contains no valid configuration")
	}
	if err := a.VerifyImportedCA(); err != nil {
		cleanup()
		return err
	}
	return nil
}

func (a *App) VerifyImportedCA() error {
	caPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-cert.pem"))
	if err != nil {
		return errors.New("imported CA certificate missing")
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return errors.New("imported CA certificate invalid")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("imported CA certificate invalid")
	}

	keyPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("imported CA key missing")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("imported CA key is invalid")
	}
	if x509.IsEncryptedPEMBlock(keyBlock) {
		// The CA key is passphrase-protected, so it cannot be decrypted here.
		// Treat the archive as valid: an encrypted key that fails to decrypt
		// will be caught later when the operator supplies the passphrase.
		return nil
	}

	caKey, err := ParseUnencryptedPrivateKeyPEM(keyPEM)
	if err != nil {
		return errors.New("imported CA key is encrypted or invalid")
	}

	caPub := caKey.PublicKey
	certPub, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok || caPub.N.Cmp(certPub.N) != 0 || caPub.E != certPub.E {
		return errors.New("imported CA key does not match the CA certificate")
	}
	return nil
}
