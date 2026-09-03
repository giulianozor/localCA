package main

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/giulianozor/localCA/internal/ca"
)

func handleIndex(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.RenderIndex(w, r, r.URL.Query().Get("msg"), r.URL.Query().Get("err"))
}

func handleSetLanguage(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	lang := strings.TrimSpace(strings.ToLower(r.FormValue("lang")))
	if !ca.IsSupportedLanguage(lang) {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(a.DefaultLang, "msg.invalid_language")), http.StatusSeeOther)
		return
	}
	cfg, hasCA, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !hasCA {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(a.DefaultLang, "msg.create_ca_before_language_change")), http.StatusSeeOther)
		return
	}
	cfg.Language = lang
	if err := a.SaveConfig(cfg); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.language_updated")), http.StatusSeeOther)
}

func handleDownload(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	kind := r.URL.Query().Get("kind")
	id := r.URL.Query().Get("id")
	if kind == "ca-all-tar-gz" {
		if _, hasCA, err := a.LoadConfig(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if !hasCA {
			http.Error(w, "CA not found", http.StatusBadRequest)
			return
		}
		exportPassphrase := strings.TrimSpace(r.URL.Query().Get("export_passphrase"))
		if err := a.WriteCAArchive(w, exportPassphrase); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if kind == "all-tar-gz" {
		path, safeID, err := a.ResolveCertificateDir(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		exportPassphrase := strings.TrimSpace(r.URL.Query().Get("export_passphrase"))
		if err := ca.WriteCertificateArchive(w, path, safeID, a.DataDir, exportPassphrase); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if kind == "client-p12" {
		path, safeID, err := a.ResolveCertificateDir(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p12Passphrase := strings.TrimSpace(r.URL.Query().Get("export_passphrase"))
		if err := ca.WriteCertificateP12(w, path, safeID, a.DataDir, p12Passphrase); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	path, filename, ctype, err := resolveDownload(a, kind, id)
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

func resolveDownload(a *ca.App, kind, id string) (string, string, string, error) {
	switch kind {
	case "ca-cert-pem":
		return filepath.Join(a.DataDir, "ca-cert.pem"), "ca-cert.pem", "application/x-pem-file", nil
	case "ca-cert-der":
		return filepath.Join(a.DataDir, "ca-cert.der"), "ca-cert.der", "application/pkix-cert", nil
	case "ca-key-pem":
		return filepath.Join(a.DataDir, "ca-key.pem"), "ca-key.pem", "application/x-pem-file", nil
	case "intermediate-cert-pem":
		return filepath.Join(a.DataDir, "intermediate-cert.pem"), "intermediate-cert.pem", "application/x-pem-file", nil
	case "intermediate-chain-pem":
		return filepath.Join(a.DataDir, "intermediate-chain.pem"), "intermediate-chain.pem", "application/x-pem-file", nil
	case "crl-pem":
		return filepath.Join(a.DataDir, "crl.pem"), "crl.pem", "application/x-pem-file", nil
	case "crl-der":
		return filepath.Join(a.DataDir, "crl.der"), "crl.der", "application/pkix-crl", nil
	case "csr-pem":
		base, safeID, err := a.ResolveCertificateDir(id)
		if err != nil {
			return "", "", "", err
		}
		return filepath.Join(base, "csr.pem"), safeID + "-csr.pem", "application/x-pem-file", nil
	default:
		return "", "", "", errors.New("unsupported download type")
	}
}
