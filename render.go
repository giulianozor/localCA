package main

import (
	"embed"
	"html/template"
	"io"
	"net/http"
	"strings"
)

func (a *app) renderIndex(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	cfg, hasCA, err := a.loadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	certs, err := a.listCerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sortCertsDesc(certs)
	filter := strings.TrimSpace(r.URL.Query().Get("q"))
	certs = filterCertificates(certs, filter)
	lang := a.currentLanguage(cfg, hasCA)

	data := pageData{
		HasCA:                    hasCA,
		HasIntermediate:          hasCA && a.hasIntermediate(),
		HasCRL:                   a.hasCRL(),
		CAYears:                  caYears,
		IntermediateYears:        intermediateYears,
		Config:                   cfg,
		Certificates:             certs,
		CertFilter:               filter,
		Message:                  msg,
		Error:                    errMsg,
		DefaultCertYears:         defaultCertValidityYears,
		MaxCertYears:             maxCertValidityYear,
		SignerPassphraseRequired: hasCA && cfg.signerPassphraseRequired(a.hasIntermediate()),
		Lang:                     lang,
		T:                        a.translations[lang],
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleStyles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = io.WriteString(w, stylesCSS)
}

func handleAppJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = io.WriteString(w, appJS)
}

//go:embed ui/index.html
var indexHTML string

//go:embed ui/styles.css
var stylesCSS string

//go:embed ui/app.js
var appJS string

//go:embed ui/cert_table_rows.html
var certTableRowsHTML string

//go:embed i18n/*.json
var embeddedI18n embed.FS

var certTableRowsTemplate = template.Must(template.New("cert-table-rows").Parse(certTableRowsHTML))

var indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
	"certTableArgs": certTableArgs,
}).Parse(indexHTML))
