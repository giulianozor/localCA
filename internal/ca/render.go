package ca

import (
	"embed"
	"html/template"
	"io"
	"net/http"
	"strings"
)

func (a *App) RenderIndex(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	cfg, hasCA, err := a.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	certs, err := a.ListCerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	SortCertsDesc(certs)
	filter := strings.TrimSpace(r.URL.Query().Get("q"))
	certs = FilterCertificates(certs, filter)
	lang := a.CurrentLanguage(cfg, hasCA)

	data := PageData{
		HasCA:                    hasCA,
		HasIntermediate:          hasCA && a.HasIntermediate(),
		HasCRL:                   a.HasCRL(),
		CAYears:                  CAYears,
		IntermediateYears:        IntermediateYears,
		Config:                   cfg,
		Certificates:             certs,
		CertFilter:               filter,
		Message:                  msg,
		Error:                    errMsg,
		DefaultCertYears:         DefaultCertValidityYears,
		MaxCertYears:             MaxCertValidityYear,
		SignerPassphraseRequired: hasCA && cfg.SignerPassphraseRequired(a.HasIntermediate()),
		Lang:                     lang,
		T:                        a.Translations[lang],
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func HandleStyles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = io.WriteString(w, stylesCSS)
}

func HandleAppJS(w http.ResponseWriter, r *http.Request) {
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
var EmbeddedI18n embed.FS

var CertTableRowsTemplate = template.Must(template.New("cert-table-rows").Parse(certTableRowsHTML))

var indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
	"certTableArgs": CertTableArgs,
}).Parse(indexHTML))
