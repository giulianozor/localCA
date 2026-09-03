package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func (a *app) handleCreateCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, has, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.currentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}

	certType := r.FormValue("cert_type")
	if certType == "" {
		certType = "server"
	}
	switch certType {
	case "server", "client", "dot1x", "codeSigning":
	default:
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.invalid_cert_type")), http.StatusSeeOther)
		return
	}
	isIdentityCert := certType != "server"
	sansInput := strings.TrimSpace(r.FormValue("sans"))
	var sans []string
	var sansErr error
	if isIdentityCert {
		sans, sansErr = parseSANsOptional(sansInput)
	} else {
		sans, sansErr = parseSANs(sansInput)
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
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.identity_cn_required")), http.StatusSeeOther)
			return
		}
	}
	years, err := parseValidityYears(r.FormValue("validity_years"))
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	keyPassphrase := strings.TrimSpace(r.FormValue("key_passphrase"))

	signer := r.FormValue("signer")
	useIntermediate := a.hasIntermediate() && signer != "ca"
	var requiresSignerPassphrase bool
	if useIntermediate {
		requiresSignerPassphrase = cfg.IntermediatePassphraseSet
	} else {
		requiresSignerPassphrase = cfg.CAPassphraseSet
	}
	signerPassphrase := strings.TrimSpace(r.FormValue("signer_passphrase"))
	if requiresSignerPassphrase && signerPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.signer_passphrase_required")), http.StatusSeeOther)
		return
	}

	if err := a.createServerCert(commonName, sans, years, keyPassphrase, signerPassphrase, useIntermediate, certType); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.cert_created")), http.StatusSeeOther)
}

func (a *app) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, has, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.currentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}

	id := strings.TrimSpace(r.FormValue("id"))
	path, safeID, err := a.resolveCertificateDir(id)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
		return
	}
	if err := os.RemoveAll(path); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.translate(lang, "msg.cert_deleted"), safeID)), http.StatusSeeOther)
}

func (a *app) handleChangeCertPassphrase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.currentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	currentPassphrase := strings.TrimSpace(r.FormValue("current_passphrase"))
	newPassphrase := strings.TrimSpace(r.FormValue("new_passphrase"))
	if err := a.changeCertificatePassphrase(id, currentPassphrase, newPassphrase); err != nil {
		if errors.Is(err, errCertificateIDInvalid) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.translate(lang, "msg.cert_passphrase_updated"), id)), http.StatusSeeOther)
}

func (a *app) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.currentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	certDir, safeID, err := a.resolveCertificateDir(id)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
		return
	}
	meta, err := a.loadCertMetadata(certDir)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if meta.RevokedAt != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(fmt.Sprintf(a.translate(lang, "msg.cert_already_revoked"), safeID)), http.StatusSeeOther)
		return
	}
	now := timeNow()
	meta.RevokedAt = &now
	if err := a.saveCertMetadata(certDir, meta); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.translate(lang, "msg.cert_revoked"), safeID)), http.StatusSeeOther)
}

func (a *app) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.currentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	certDir, safeID, err := a.resolveCertificateDir(id)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.invalid_cert_id")), http.StatusSeeOther)
		return
	}
	meta, err := a.loadCertMetadata(certDir)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	keyPassphrase := strings.TrimSpace(r.FormValue("key_passphrase"))
	signerPassphrase := strings.TrimSpace(r.FormValue("signer_passphrase"))
	if cfg.signerPassphraseRequired(a.hasIntermediate()) && signerPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.signer_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.createServerCert(meta.CommonName, meta.SANs, meta.ValidityYears, keyPassphrase, signerPassphrase, a.hasIntermediate(), meta.CertType()); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if meta.RevokedAt == nil {
		now := timeNow()
		meta.RevokedAt = &now
		if err := a.saveCertMetadata(certDir, meta); err != nil {
			http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.translate(lang, "msg.cert_renewed"), safeID)), http.StatusSeeOther)
}

func (a *app) handleGenerateCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.currentLanguage(cfg, has)
	if !has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
		return
	}
	signerPassphrase := strings.TrimSpace(r.FormValue("signer_passphrase"))
	if cfg.signerPassphraseRequired(a.hasIntermediate()) && signerPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.signer_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.generateCRL(lang, signerPassphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.crl_generated")), http.StatusSeeOther)
}

func (a *app) handleCertTable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, hasCA, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lang := a.currentLanguage(cfg, hasCA)
	certs, err := a.listCerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sortCertsDesc(certs)
	certs = filterCertificates(certs, r.URL.Query().Get("q"))
	if certType := r.URL.Query().Get("type"); certType != "" {
		switch certType {
		case "server", "client", "dot1x", "codeSigning":
			certs = filterCertificatesByType(certs, certType)
		default:
			http.Error(w, "unknown certificate type", http.StatusBadRequest)
			return
		}
	}
	data := pageData{
		Certificates:             certs,
		SignerPassphraseRequired: hasCA && cfg.signerPassphraseRequired(a.hasIntermediate()),
		T:                        a.translations[lang],
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := certTableRowsTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
