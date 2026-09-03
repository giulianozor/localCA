package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/giulianozor/localCA/internal/ca"
)

func handleCreateCA(a *ca.App, w http.ResponseWriter, r *http.Request) {
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
	if has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.ca_already_exists")), http.StatusSeeOther)
		return
	}

	cn := strings.TrimSpace(r.FormValue("ca_common_name"))
	if cn == "" {
		cn = "localCA Root"
	}
	org := strings.TrimSpace(r.FormValue("organization"))
	if org == "" {
		org = "localCA"
	}
	country := strings.TrimSpace(r.FormValue("country"))
	if country == "" {
		country = "IT"
	}
	passphrase := strings.TrimSpace(r.FormValue("ca_passphrase"))

	if err := a.CreateCA(cn, org, country, passphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.ca_created")), http.StatusSeeOther)
}

func handleChangeCAPassphrase(a *ca.App, w http.ResponseWriter, r *http.Request) {
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
	currentPassphrase := strings.TrimSpace(r.FormValue("current_passphrase"))
	newPassphrase := strings.TrimSpace(r.FormValue("new_passphrase"))
	if cfg.CAPassphraseSet && currentPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.ChangeCAPassphrase(currentPassphrase, newPassphrase); err != nil {
		if errors.Is(err, ca.ErrCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.ca_passphrase_updated")), http.StatusSeeOther)
}

func handleRenewCA(a *ca.App, w http.ResponseWriter, r *http.Request) {
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
	caPassphrase := strings.TrimSpace(r.FormValue("ca_passphrase"))
	if cfg.CAPassphraseSet && caPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.RenewCA(caPassphrase); err != nil {
		if errors.Is(err, ca.ErrCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.ca_renewed")), http.StatusSeeOther)
}

func handleCreateIntermediate(a *ca.App, w http.ResponseWriter, r *http.Request) {
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
	if a.HasIntermediate() {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.intermediate_already_exists")), http.StatusSeeOther)
		return
	}

	cn := strings.TrimSpace(r.FormValue("intermediate_common_name"))
	if cn == "" {
		cn = "localCA Intermediate"
	}
	org := strings.TrimSpace(r.FormValue("intermediate_organization"))
	if org == "" {
		org = cfg.Organization
		if org == "" {
			org = "localCA"
		}
	}
	country := strings.TrimSpace(r.FormValue("intermediate_country"))
	if country == "" {
		country = cfg.Country
		if country == "" {
			country = "IT"
		}
	}
	caPassphrase := strings.TrimSpace(r.FormValue("ca_passphrase"))
	if cfg.CAPassphraseSet && caPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	passphrase := strings.TrimSpace(r.FormValue("intermediate_passphrase"))

	if err := a.CreateIntermediateCA(cn, org, country, caPassphrase, passphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.intermediate_created")), http.StatusSeeOther)
}

func handleRenewIntermediate(a *ca.App, w http.ResponseWriter, r *http.Request) {
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
	if !a.HasIntermediate() {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_intermediate_first")), http.StatusSeeOther)
		return
	}
	caPassphrase := strings.TrimSpace(r.FormValue("ca_passphrase"))
	if cfg.CAPassphraseSet && caPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.RenewIntermediateCA(caPassphrase); err != nil {
		if errors.Is(err, ca.ErrCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.intermediate_renewed")), http.StatusSeeOther)
}

func handleChangeIntermediatePassphrase(a *ca.App, w http.ResponseWriter, r *http.Request) {
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
	if !a.HasIntermediate() {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_intermediate_first")), http.StatusSeeOther)
		return
	}
	currentPassphrase := strings.TrimSpace(r.FormValue("current_passphrase"))
	newPassphrase := strings.TrimSpace(r.FormValue("new_passphrase"))
	if cfg.IntermediatePassphraseSet && currentPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.intermediate_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.ChangeIntermediatePassphrase(currentPassphrase, newPassphrase); err != nil {
		if errors.Is(err, ca.ErrCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(lang, "msg.intermediate_passphrase_updated")), http.StatusSeeOther)
}

func handleImportCA(a *ca.App, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(ca.MaxImportArchive); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("invalid form upload"), http.StatusSeeOther)
		return
	}

	file, _, err := r.FormFile("archive")
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("no archive file provided"), http.StatusSeeOther)
		return
	}
	defer file.Close()

	importPassphrase := strings.TrimSpace(r.FormValue("import_passphrase"))
	if err := a.ImportCAArchive(file, importPassphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.Translate(a.DefaultLang, "msg.ca_import_failed")+": "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.Translate(a.DefaultLang, "msg.ca_imported")), http.StatusSeeOther)
}
