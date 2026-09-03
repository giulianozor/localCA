package main

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.renderIndex(w, r, r.URL.Query().Get("msg"), r.URL.Query().Get("err"))
}

func (a *app) handleSetLanguage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	lang := strings.TrimSpace(strings.ToLower(r.FormValue("lang")))
	if !isSupportedLanguage(lang) {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(a.defaultLang, "msg.invalid_language")), http.StatusSeeOther)
		return
	}
	cfg, hasCA, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !hasCA {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(a.defaultLang, "msg.create_ca_before_language_change")), http.StatusSeeOther)
		return
	}
	cfg.Language = lang
	if err := a.saveConfig(cfg); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.language_updated")), http.StatusSeeOther)
}

func (a *app) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	kind := r.URL.Query().Get("kind")
	id := r.URL.Query().Get("id")
	if kind == "ca-all-tar-gz" {
		if _, hasCA, err := a.loadConfig(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if !hasCA {
			http.Error(w, "CA not found", http.StatusBadRequest)
			return
		}
		exportPassphrase := strings.TrimSpace(r.URL.Query().Get("export_passphrase"))
		if err := a.writeCAArchive(w, exportPassphrase); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if kind == "all-tar-gz" {
		path, safeID, err := a.resolveCertificateDir(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		exportPassphrase := strings.TrimSpace(r.URL.Query().Get("export_passphrase"))
		if err := writeCertificateArchive(w, path, safeID, a.dataDir, exportPassphrase); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if kind == "client-p12" {
		path, safeID, err := a.resolveCertificateDir(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p12Passphrase := strings.TrimSpace(r.URL.Query().Get("export_passphrase"))
		if err := writeCertificateP12(w, path, safeID, a.dataDir, p12Passphrase); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	path, filename, ctype, err := a.resolveDownload(kind, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	_, _ = io.Copy(w, f)
}

// timeNow returns the current time, separated for testing clarity.
func timeNow() time.Time {
	return time.Now()
}

func sortCertsDesc(certs []certMetadata) {
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].CreatedAt.After(certs[j].CreatedAt)
	})
}

func (a *app) resolveDownload(kind, id string) (string, string, string, error) {
	switch kind {
	case "ca-cert-pem":
		return filepath.Join(a.dataDir, "ca-cert.pem"), "ca-cert.pem", "application/x-pem-file", nil
	case "ca-cert-der":
		return filepath.Join(a.dataDir, "ca-cert.der"), "ca-cert.der", "application/pkix-cert", nil
	case "ca-key-pem":
		return filepath.Join(a.dataDir, "ca-key.pem"), "ca-key.pem", "application/x-pem-file", nil
	case "intermediate-cert-pem":
		return filepath.Join(a.dataDir, "intermediate-cert.pem"), "intermediate-cert.pem", "application/x-pem-file", nil
	case "intermediate-chain-pem":
		return filepath.Join(a.dataDir, "intermediate-chain.pem"), "intermediate-chain.pem", "application/x-pem-file", nil
	case "crl-pem":
		return filepath.Join(a.dataDir, "crl.pem"), "crl.pem", "application/x-pem-file", nil
	case "crl-der":
		return filepath.Join(a.dataDir, "crl.der"), "crl.der", "application/pkix-crl", nil
	case "csr-pem":
		base, safeID, err := a.resolveCertificateDir(id)
		if err != nil {
			return "", "", "", err
		}
		return filepath.Join(base, "csr.pem"), safeID + "-csr.pem", "application/x-pem-file", nil
	default:
		return "", "", "", errors.New("unsupported download type")
	}
}
