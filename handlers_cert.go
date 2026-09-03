package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/giulianozor/localCA/internal/ca"
)

func handleCreateCert(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, has, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.CurrentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}

	certType := r.FormValue("cert_type")
	if certType == "" {
		certType = "server"
	}
	switch certType {
	case "server", "client", "dot1x", "codeSigning":
	default:
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.invalid_cert_type")), http.StatusSeeOther)
		return
	}
	isIdentityCert := certType != "server"
	sansInput := strings.TrimSpace(r.FormValue("sans"))
	var sans []string
	var sansErr error
	if isIdentityCert {
		sans, sansErr = ca.ParseSANsOptional(sansInput)
	} else {
		sans, sansErr = ca.ParseSANs(sansInput)
	}
	if sansErr != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(sansErr.Error()), http.StatusSeeOther)
		return
	}
	commonName := strings.TrimSpace(r.FormValue("common_name"))
	if commonName == "" {
		if len(sans) > 0 {
			commonName = sans[0]
		} else if isIdentityCert {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.identity_cn_required")), http.StatusSeeOther)
			return
		}
	}
	years, err := ca.ParseValidityYears(r.FormValue("validity_years"))
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	keyPassphrase := strings.TrimSpace(r.FormValue("key_passphrase"))

	signer := r.FormValue("signer")
	useIntermediate := a.HasIntermediate() && signer != "ca"
	var requiresSignerPassphrase bool
	if useIntermediate {
		requiresSignerPassphrase = cfg.IntermediatePassphraseSet
	} else {
		requiresSignerPassphrase = cfg.CAPassphraseSet
	}
	signerPassphrase := strings.TrimSpace(r.FormValue("signer_passphrase"))
	if requiresSignerPassphrase && signerPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.signer_passphrase_required")), http.StatusSeeOther)
		return
	}

	if err := a.CreateServerCert(commonName, sans, years, keyPassphrase, signerPassphrase, useIntermediate, certType); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.cert_created")), http.StatusSeeOther)
}

func handleDeleteCert(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, has, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.CurrentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}

	id := strings.TrimSpace(r.FormValue("id"))
	path, safeID, err := a.ResolveCertificateDir(id)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
		return
	}
	if err := os.RemoveAll(path); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.Translate(lang, "msg.cert_deleted"), safeID)), http.StatusSeeOther)
}

func handleChangeCertPassphrase(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.CurrentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	currentPassphrase := strings.TrimSpace(r.FormValue("current_passphrase"))
	newPassphrase := strings.TrimSpace(r.FormValue("new_passphrase"))
	err = a.ChangeCertificatePassphrase(
		id,
		currentPassphrase,
		newPassphrase,
		a.Translate(lang, "msg.cert_passphrase_required"),
		a.Translate(lang, "msg.cert_passphrase_invalid"),
	)
	if err != nil {
		if errors.Is(err, ca.ErrCertificateIDInvalid) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.Translate(lang, "msg.cert_passphrase_updated"), id)), http.StatusSeeOther)
}

func handleRevokeCert(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.CurrentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	certDir, safeID, err := a.ResolveCertificateDir(id)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
		return
	}
	meta, err := a.LoadCertMetadata(certDir)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if meta.RevokedAt != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(fmt.Sprintf(a.Translate(lang, "msg.cert_already_revoked"), safeID)), http.StatusSeeOther)
		return
	}
	now := timeNow()
	meta.RevokedAt = &now
	if err := a.SaveCertMetadata(certDir, meta); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.Translate(lang, "msg.cert_revoked"), safeID)), http.StatusSeeOther)
}

func handleRenewCert(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.CurrentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	certDir, safeID, err := a.ResolveCertificateDir(id)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
		return
	}
	meta, err := a.LoadCertMetadata(certDir)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	keyPassphrase := strings.TrimSpace(r.FormValue("key_passphrase"))
	signerPassphrase := strings.TrimSpace(r.FormValue("signer_passphrase"))
	// Re-sign under the same signer that originally issued the certificate
	// (legacy metadata without a signer falls back to the current default).
	useIntermediate := meta.SignerName(a.HasIntermediate()) == "intermediate"
	if useIntermediate {
		if cfg.IntermediatePassphraseSet && signerPassphrase == "" {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.intermediate_passphrase_required")), http.StatusSeeOther)
			return
		}
	} else if cfg.CAPassphraseSet && signerPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.CreateServerCert(meta.CommonName, meta.SANs, meta.ValidityYears, keyPassphrase, signerPassphrase, useIntermediate, meta.CertType()); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if meta.RevokedAt == nil {
		now := timeNow()
		meta.RevokedAt = &now
		if err := a.SaveCertMetadata(certDir, meta); err != nil {
			http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.Translate(lang, "msg.cert_renewed"), safeID)), http.StatusSeeOther)
}

func handleGenerateCRL(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.CurrentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	signerPassphrase := strings.TrimSpace(r.FormValue("signer_passphrase"))
	if cfg.SignerPassphraseRequired(a.HasIntermediate()) && signerPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.signer_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.GenerateCRL(lang, signerPassphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.crl_generated")), http.StatusSeeOther)
}

func handleCertTable(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, hasCA, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.CurrentLanguage(cfg, hasCA)
	certs, err := a.ListCerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ca.SortCertsDesc(certs)
	certs = ca.FilterCertificates(certs, r.URL.Query().Get("q"))
	if certType := r.URL.Query().Get("type"); certType != "" {
		switch certType {
		case "server", "client", "dot1x", "codeSigning":
			certs = ca.FilterCertificatesByType(certs, certType)
		default:
			http.Error(w, "unknown certificate type", http.StatusBadRequest)
			return
		}
	}
	data := ca.PageData{
		Certificates:             certs,
		SignerPassphraseRequired: hasCA && cfg.SignerPassphraseRequired(a.HasIntermediate()),
		T:                        a.Translations[lang],
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ca.CertTableRowsTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
