package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	caYears                  = 100
	intermediateYears        = 30
	maxCertValidityYear      = 30
	defaultCertValidityYears = 2
	defaultLanguage          = "en"
	certNotBeforeOffset      = -1 * time.Hour
	crlNextUpdateDays        = 7

	caArchiveMagic   = "localCA-CA-ARCHIVE-V1" // magic prefix for encrypted CA archives
	caEncKeyIter     = 210000                  // PBKDF2 iterations for CA archive encryption
	caEncKeyLen      = 32
	caEncSaltLen     = 16
	caEncNonceLen    = 12
	maxImportArchive = 512 << 20 // 512 MB cap for imported CA archives
)

const (
	archiveCryptNone uint8 = iota
	archiveCryptAESGCM
)

var (
	errCAConfigNotFound     = errors.New("ca configuration not found")
	errCertificateIDInvalid = errors.New("invalid certificate id")
)

type app struct {
	dataDir      string
	defaultLang  string
	translations map[string]map[string]string
}

type config struct {
	CreatedAt                 time.Time `json:"created_at"`
	CACommonName              string    `json:"ca_common_name"`
	Organization              string    `json:"organization"`
	Country                   string    `json:"country"`
	CAValidityYears           int       `json:"ca_validity_years"`
	Language                  string    `json:"language"`
	CAPassphraseSet           bool      `json:"ca_passphrase_set,omitempty"`
	HasIntermediate           bool      `json:"has_intermediate,omitempty"`
	IntermediateCommonName    string    `json:"intermediate_common_name,omitempty"`
	IntermediateOrganization  string    `json:"intermediate_organization,omitempty"`
	IntermediateCountry       string    `json:"intermediate_country,omitempty"`
	IntermediateValidityYears int       `json:"intermediate_validity_years,omitempty"`
	IntermediatePassphraseSet bool      `json:"intermediate_passphrase_set,omitempty"`
}

type certMetadata struct {
	ID            string     `json:"id"`
	CommonName    string     `json:"common_name"`
	SANs          []string   `json:"sans"`
	Type          string     `json:"type,omitempty"`   // server, client, dot1x
	Client        bool       `json:"client,omitempty"` // legacy field, kept for older metadata files
	ValidityYears int        `json:"validity_years"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// CertType returns the normalized certificate type, mapping legacy metadata
// (which only tracked the Client flag) onto the current "type" values.
func (c certMetadata) CertType() string {
	if c.Type != "" {
		return c.Type
	}
	if c.Client {
		return "client"
	}
	return "server"
}

func (c config) signerPassphraseRequired(hasIntermediate bool) bool {
	if hasIntermediate {
		return c.IntermediatePassphraseSet
	}
	return c.CAPassphraseSet
}

type pageData struct {
	HasCA                    bool
	HasIntermediate          bool
	HasCRL                   bool
	CAYears                  int
	IntermediateYears        int
	Config                   config
	Certificates             []certMetadata
	CertFilter               string
	Message                  string
	Error                    string
	DefaultCertYears         int
	MaxCertYears             int
	SignerPassphraseRequired bool
	Lang                     string
	T                        map[string]string
}

// certTableCtx carries the data needed to render the certificate table for a
// single certificate type inside the tabbed index page.
type certTableCtx struct {
	T            map[string]string
	CertType     string
	Title        string
	CertFilter   string
	Certificates []certMetadata
}

// certTableArgs returns the rendering context for a certificate type's table,
// filtering the full certificate list down to the requested type.
func certTableArgs(root pageData, certType, title string) certTableCtx {
	return certTableCtx{
		T:            root.T,
		CertType:     certType,
		Title:        title,
		CertFilter:   root.CertFilter,
		Certificates: filterCertificatesByType(root.Certificates, certType),
	}
}

func main() {
	dataDir, port, lang, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("usage: %s [-port 8080] [-lang en|it|ja] <data-directory>: %v", os.Args[0], err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "certs"), 0o750); err != nil {
		log.Fatalf("unable to create data directory: %v", err)
	}
	translations, err := loadTranslations()
	if err != nil {
		log.Fatalf("unable to load translations: %v", err)
	}

	a := &app{dataDir: dataDir, defaultLang: lang, translations: translations}
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/lang", a.handleSetLanguage)
	mux.HandleFunc("/ca/create", a.handleCreateCA)
	mux.HandleFunc("/ca/import", a.handleImportCA)
	mux.HandleFunc("/ca/passphrase", a.handleChangeCAPassphrase)
	mux.HandleFunc("/ca/renew", a.handleRenewCA)
	mux.HandleFunc("/intermediate/create", a.handleCreateIntermediate)
	mux.HandleFunc("/intermediate/renew", a.handleRenewIntermediate)
	mux.HandleFunc("/intermediate/passphrase", a.handleChangeIntermediatePassphrase)
	mux.HandleFunc("/certs/create", a.handleCreateCert)
	mux.HandleFunc("/certs/passphrase", a.handleChangeCertPassphrase)
	mux.HandleFunc("/certs/revoke", a.handleRevokeCert)
	mux.HandleFunc("/certs/renew", a.handleRenewCert)
	mux.HandleFunc("/certs/delete", a.handleDeleteCert)
	mux.HandleFunc("/certs/table", a.handleCertTable)
	mux.HandleFunc("/certs/crl/generate", a.handleGenerateCRL)
	mux.HandleFunc("/download", a.handleDownload)
	mux.HandleFunc("/static/styles.css", handleStyles)
	mux.HandleFunc("/static/app.js", handleAppJS)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("localCA UI available on all interfaces (port %d), access via http://<host-ip-or-hostname>:%d", port, port)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func parseArgs(args []string) (string, int, string, error) {
	fs := flag.NewFlagSet("localCA", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", 8080, "HTTP port for the web server")
	lang := fs.String("lang", defaultLanguage, "UI language (en|it|ja)")
	if err := fs.Parse(args); err != nil {
		return "", 0, "", err
	}
	if *port < 1 || *port > 65535 {
		return "", 0, "", errors.New("invalid port: use a value between 1 and 65535")
	}
	if !isSupportedLanguage(*lang) {
		return "", 0, "", errors.New("invalid language: use en, it or ja")
	}
	remaining := fs.Args()
	if len(remaining) != 1 {
		return "", 0, "", errors.New("specify data directory path")
	}
	return remaining[0], *port, *lang, nil
}

func loadTranslations() (map[string]map[string]string, error) {
	result := map[string]map[string]string{}
	for _, lang := range []string{"it", "en", "ja"} {
		path := filepath.Join("i18n", lang+".json")
		b, err := embeddedI18n.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var stringsMap map[string]string
		if err := json.Unmarshal(b, &stringsMap); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", path, err)
		}
		result[lang] = stringsMap
	}
	return result, nil
}

func isSupportedLanguage(lang string) bool {
	switch lang {
	case "en", "it", "ja":
		return true
	default:
		return false
	}
}

func (a *app) currentLanguage(cfg config, hasCA bool) string {
	if hasCA && isSupportedLanguage(cfg.Language) {
		return cfg.Language
	}
	if isSupportedLanguage(a.defaultLang) {
		return a.defaultLang
	}
	return defaultLanguage
}

func (a *app) translate(lang, key string) string {
	if m, ok := a.translations[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := a.translations[defaultLanguage]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

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

	sort.Slice(certs, func(i, j int) bool {
		return certs[i].CreatedAt.After(certs[j].CreatedAt)
	})
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
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].CreatedAt.After(certs[j].CreatedAt)
	})
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

func (a *app) handleCreateCA(w http.ResponseWriter, r *http.Request) {
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
	if has {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.ca_already_exists")), http.StatusSeeOther)
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

	if err := a.createCA(cn, org, country, passphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.ca_created")), http.StatusSeeOther)
}

func (a *app) handleCreateIntermediate(w http.ResponseWriter, r *http.Request) {
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
	if a.hasIntermediate() {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.intermediate_already_exists")), http.StatusSeeOther)
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
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	passphrase := strings.TrimSpace(r.FormValue("intermediate_passphrase"))

	if err := a.createIntermediateCA(cn, org, country, caPassphrase, passphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.intermediate_created")), http.StatusSeeOther)
}

func (a *app) handleChangeCAPassphrase(w http.ResponseWriter, r *http.Request) {
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
	currentPassphrase := strings.TrimSpace(r.FormValue("current_passphrase"))
	newPassphrase := strings.TrimSpace(r.FormValue("new_passphrase"))
	if cfg.CAPassphraseSet && currentPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.changeCAPassphrase(currentPassphrase, newPassphrase); err != nil {
		if errors.Is(err, errCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.ca_passphrase_updated")), http.StatusSeeOther)
}

func (a *app) handleChangeIntermediatePassphrase(w http.ResponseWriter, r *http.Request) {
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
	if !a.hasIntermediate() {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_intermediate_first")), http.StatusSeeOther)
		return
	}
	currentPassphrase := strings.TrimSpace(r.FormValue("current_passphrase"))
	newPassphrase := strings.TrimSpace(r.FormValue("new_passphrase"))
	if cfg.IntermediatePassphraseSet && currentPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.signer_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.changeIntermediatePassphrase(currentPassphrase, newPassphrase); err != nil {
		if errors.Is(err, errCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.intermediate_passphrase_updated")), http.StatusSeeOther)
}

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
	now := time.Now()
	meta.RevokedAt = &now
	if err := a.saveCertMetadata(certDir, meta); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.translate(lang, "msg.cert_revoked"), safeID)), http.StatusSeeOther)
}

func (a *app) generateCRL(lang, signerPassphrase string) error {
	signerCertPath := filepath.Join(a.dataDir, "ca-cert.pem")
	signerKeyPath := filepath.Join(a.dataDir, "ca-key.pem")
	missingErr := a.translate(lang, "msg.ca_passphrase_required")
	invalidErr := a.translate(lang, "msg.ca_passphrase_invalid")
	if a.hasIntermediate() {
		signerCertPath = filepath.Join(a.dataDir, "intermediate-cert.pem")
		signerKeyPath = filepath.Join(a.dataDir, "intermediate-key.pem")
		missingErr = a.translate(lang, "msg.intermediate_passphrase_required")
		invalidErr = a.translate(lang, "msg.intermediate_passphrase_invalid")
	}
	signerCertPEM, err := os.ReadFile(signerCertPath)
	if err != nil {
		return errors.New(a.translate(lang, "msg.crl_signer_cert_not_found"))
	}
	signerBlock, _ := pem.Decode(signerCertPEM)
	if signerBlock == nil {
		return errors.New(a.translate(lang, "msg.crl_signer_cert_invalid"))
	}
	signerCert, err := x509.ParseCertificate(signerBlock.Bytes)
	if err != nil {
		return err
	}
	signerKeyPEM, err := os.ReadFile(signerKeyPath)
	if err != nil {
		return errors.New(a.translate(lang, "msg.crl_signer_key_not_found"))
	}
	signerKey, err := parsePrivateKeyPEM(signerKeyPEM, signerPassphrase, missingErr, invalidErr)
	if err != nil {
		return err
	}

	certs, err := a.listCerts()
	if err != nil {
		return err
	}
	var revokedCerts []x509.RevocationListEntry
	for _, meta := range certs {
		if meta.RevokedAt == nil {
			continue
		}
		certDir := filepath.Join(a.dataDir, "certs", meta.ID)
		certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
		if err != nil {
			log.Printf("generateCRL: skipping cert %s: read cert.pem: %v", meta.ID, err)
			continue
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			log.Printf("generateCRL: skipping cert %s: no PEM block in cert.pem", meta.ID)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("generateCRL: skipping cert %s: parse cert.pem: %v", meta.ID, err)
			continue
		}
		revokedCerts = append(revokedCerts, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: *meta.RevokedAt,
		})
	}

	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		// NextUpdate tells CRL consumers how long this CRL is valid.
		NextUpdate:                now.AddDate(0, 0, crlNextUpdateDays),
		RevokedCertificateEntries: revokedCerts,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, signerCert, signerKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(a.dataDir, "crl.pem"), "X509 CRL", crlDER, 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.dataDir, "crl.der"), crlDER, 0o640)
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
		now := time.Now()
		meta.RevokedAt = &now
		if err := a.saveCertMetadata(certDir, meta); err != nil {
			http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(fmt.Sprintf(a.translate(lang, "msg.cert_renewed"), safeID)), http.StatusSeeOther)
}

func (a *app) handleRenewCA(w http.ResponseWriter, r *http.Request) {
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
	caPassphrase := strings.TrimSpace(r.FormValue("ca_passphrase"))
	if cfg.CAPassphraseSet && caPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.renewCA(caPassphrase); err != nil {
		if errors.Is(err, errCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.ca_renewed")), http.StatusSeeOther)
}

func (a *app) handleRenewIntermediate(w http.ResponseWriter, r *http.Request) {
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
	if !a.hasIntermediate() {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_intermediate_first")), http.StatusSeeOther)
		return
	}
	caPassphrase := strings.TrimSpace(r.FormValue("ca_passphrase"))
	if cfg.CAPassphraseSet && caPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.ca_passphrase_required")), http.StatusSeeOther)
		return
	}
	if err := a.renewIntermediateCA(caPassphrase); err != nil {
		if errors.Is(err, errCAConfigNotFound) {
			http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.create_ca_first")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.intermediate_renewed")), http.StatusSeeOther)
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

func (a *app) handleImportCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(maxImportArchive); err != nil {
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
	if err := a.importCAArchive(file, importPassphrase); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(a.defaultLang, "msg.ca_import_failed")+": "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(a.defaultLang, "msg.ca_imported")), http.StatusSeeOther)
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

func (a *app) resolveCertificateDir(id string) (string, string, error) {
	if id == "" {
		return "", "", errors.New("missing certificate ID")
	}
	entries, err := os.ReadDir(filepath.Join(a.dataDir, "certs"))
	if err != nil {
		return "", "", errors.New("certificate archive not available")
	}
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() == id {
			return filepath.Join(a.dataDir, "certs", entry.Name()), entry.Name(), nil
		}
	}
	return "", "", errors.New("invalid certificate ID")
}

func parseValidityYears(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultCertValidityYears, nil
	}
	years, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("invalid validity value")
	}
	if years < 1 || years > maxCertValidityYear {
		return 0, fmt.Errorf("validity must be between 1 and %d years", maxCertValidityYear)
	}
	return years, nil
}

func parseSANs(input string) ([]string, error) {
	parts := strings.Split(input, ",")
	seen := map[string]struct{}{}
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(strings.ToLower(p))
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	if len(result) == 0 {
		return nil, errors.New("enter at least one SAN (FQDN, IP, or hostname)")
	}
	return result, nil
}

// parseSANsOptional parses a comma-separated SAN list, returning an empty
// slice (not an error) when the input is blank. Used for client certificates,
// where the CommonName is the identity and SANs are not required.
func parseSANsOptional(input string) ([]string, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	return parseSANs(input)
}

func splitSANs(sans []string) ([]string, []net.IP) {
	dnsNames := make([]string, 0, len(sans))
	ipAddresses := make([]net.IP, 0, len(sans))
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
			continue
		}
		dnsNames = append(dnsNames, san)
	}
	return dnsNames, ipAddresses
}

func filterCertificates(certs []certMetadata, query string) []certMetadata {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return certs
	}
	filtered := make([]certMetadata, 0, len(certs))
	for _, cert := range certs {
		if strings.Contains(strings.ToLower(cert.ID), query) ||
			strings.Contains(strings.ToLower(cert.CommonName), query) ||
			strings.Contains(strings.ToLower(strings.Join(cert.SANs, ",")), query) {
			filtered = append(filtered, cert)
		}
	}
	return filtered
}

// filterCertificatesByType keeps only certificates of the given type
// (server, client, dot1x or codeSigning).
func filterCertificatesByType(certs []certMetadata, certType string) []certMetadata {
	filtered := make([]certMetadata, 0, len(certs))
	for _, cert := range certs {
		if cert.CertType() == certType {
			filtered = append(filtered, cert)
		}
	}
	return filtered
}

func (a *app) hasIntermediate() bool {
	if _, err := os.Stat(filepath.Join(a.dataDir, "intermediate-cert.pem")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(a.dataDir, "intermediate-key.pem")); err != nil {
		return false
	}
	return true
}

func (a *app) hasCRL() bool {
	_, err := os.Stat(filepath.Join(a.dataDir, "crl.pem"))
	return err == nil
}

func parsePrivateKeyPEM(keyPEM []byte, passphrase, missingErr, invalidErr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New(invalidErr)
	}
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if passphrase == "" {
			return nil, errors.New(missingErr)
		}
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, errors.New(invalidErr)
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New(invalidErr)
	}
	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New(invalidErr)
	}
	return rsaKey, nil
}

func parseUnencryptedPrivateKeyPEM(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || x509.IsEncryptedPEMBlock(block) {
		return nil, errors.New("private key is encrypted or invalid")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unsupported private key type")
	}
	return rsaKey, nil
}

func updatePrivateKeyPassphrase(path, currentPassphrase, newPassphrase, missingErr, invalidErr string) error {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	key, err := parsePrivateKeyPEM(keyPEM, currentPassphrase, missingErr, invalidErr)
	if err != nil {
		return err
	}
	updatedKeyPEM, err := encodePrivateKeyPEM(key, newPassphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(path, updatedKeyPEM, 0o600)
}

func encodePrivateKeyPEM(key *rsa.PrivateKey, passphrase string) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(key)
	if passphrase == "" {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

func (a *app) createCA(cn, org, country, passphrase string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:             now.Add(certNotBeforeOffset),
		NotAfter:              now.AddDate(caYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	if err := writePEM(filepath.Join(a.dataDir, "ca-cert.pem"), "CERTIFICATE", der, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.dataDir, "ca-cert.der"), der, 0o640); err != nil {
		return err
	}
	keyPEM, err := encodePrivateKeyPEM(privateKey, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.dataDir, "ca-key.pem"), keyPEM, 0o600); err != nil {
		return err
	}

	cfg := config{
		CreatedAt:       now,
		CACommonName:    cn,
		Organization:    org,
		Country:         country,
		CAValidityYears: caYears,
		Language:        a.defaultLang,
		CAPassphraseSet: passphrase != "",
	}
	return a.saveConfig(cfg)
}

func (a *app) createIntermediateCA(cn, org, country, caPassphrase, passphrase string) error {
	caCertPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-cert.pem"))
	if err != nil {
		return errors.New("CA certificate not found")
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return errors.New("invalid CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("CA key not found")
	}
	caKey, err := parsePrivateKeyPEM(caKeyPEM, caPassphrase, "CA passphrase required", "invalid CA passphrase")
	if err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:             now.Add(certNotBeforeOffset),
		NotAfter:              now.AddDate(intermediateYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(a.dataDir, "intermediate-cert.pem"), "CERTIFICATE", certDER, 0o640); err != nil {
		return err
	}
	keyPEM, err := encodePrivateKeyPEM(key, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.dataDir, "intermediate-key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chain = append(chain, caCertPEM...)
	if err := os.WriteFile(filepath.Join(a.dataDir, "intermediate-chain.pem"), chain, 0o640); err != nil {
		return err
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errors.New("CA configuration not found")
	}
	cfg.HasIntermediate = true
	cfg.IntermediateCommonName = cn
	cfg.IntermediateOrganization = org
	cfg.IntermediateCountry = country
	cfg.IntermediateValidityYears = intermediateYears
	cfg.IntermediatePassphraseSet = passphrase != ""
	return a.saveConfig(cfg)
}

func (a *app) renewCA(caPassphrase string) error {
	cfg, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errCAConfigNotFound
	}

	caKeyPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("CA key not found")
	}
	caKey, err := parsePrivateKeyPEM(caKeyPEM, caPassphrase, "CA passphrase required", "invalid CA passphrase")
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   cfg.CACommonName,
			Organization: []string{cfg.Organization},
			Country:      []string{cfg.Country},
		},
		NotBefore:             now.Add(certNotBeforeOffset),
		NotAfter:              now.AddDate(caYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	if err := writePEM(filepath.Join(a.dataDir, "ca-cert.pem"), "CERTIFICATE", der, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.dataDir, "ca-cert.der"), der, 0o640); err != nil {
		return err
	}
	return nil
}

func (a *app) renewIntermediateCA(caPassphrase string) error {
	cfg, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errCAConfigNotFound
	}
	if !a.hasIntermediate() {
		return errors.New("no intermediate certificate to renew")
	}

	caCertPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-cert.pem"))
	if err != nil {
		return errors.New("CA certificate not found")
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return errors.New("invalid CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("CA key not found")
	}
	caKey, err := parsePrivateKeyPEM(caKeyPEM, caPassphrase, "CA passphrase required", "invalid CA passphrase")
	if err != nil {
		return err
	}

	intCertPEM, err := os.ReadFile(filepath.Join(a.dataDir, "intermediate-cert.pem"))
	if err != nil {
		return errors.New("intermediate certificate not found")
	}
	intBlock, _ := pem.Decode(intCertPEM)
	if intBlock == nil {
		return errors.New("invalid intermediate certificate")
	}
	intCert, err := x509.ParseCertificate(intBlock.Bytes)
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   cfg.IntermediateCommonName,
			Organization: []string{cfg.IntermediateOrganization},
			Country:      []string{cfg.IntermediateCountry},
		},
		NotBefore:             now.Add(certNotBeforeOffset),
		NotAfter:              now.AddDate(intermediateYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, intCert.PublicKey, caKey)
	if err != nil {
		return err
	}

	if err := writePEM(filepath.Join(a.dataDir, "intermediate-cert.pem"), "CERTIFICATE", certDER, 0o640); err != nil {
		return err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chain = append(chain, caCertPEM...)
	if err := os.WriteFile(filepath.Join(a.dataDir, "intermediate-chain.pem"), chain, 0o640); err != nil {
		return err
	}
	return nil
}

func (a *app) createServerCert(commonName string, sans []string, years int, keyPassphrase, signerPassphrase string, useIntermediate bool, certType string) error {
	signerCertPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-cert.pem"))
	if err != nil {
		return errors.New("CA certificate not found")
	}
	signerName := "CA"
	signerKeyPath := filepath.Join(a.dataDir, "ca-key.pem")
	if useIntermediate {
		signerCertPEM, err = os.ReadFile(filepath.Join(a.dataDir, "intermediate-cert.pem"))
		if err != nil {
			return errors.New("intermediate certificate not found")
		}
		signerName = "intermediate"
		signerKeyPath = filepath.Join(a.dataDir, "intermediate-key.pem")
	}
	signerBlock, _ := pem.Decode(signerCertPEM)
	if signerBlock == nil {
		return fmt.Errorf("invalid %s certificate PEM", signerName)
	}
	signerCert, err := x509.ParseCertificate(signerBlock.Bytes)
	if err != nil {
		return err
	}

	signerKeyPEM, err := os.ReadFile(signerKeyPath)
	if err != nil {
		return fmt.Errorf("%s key not found", signerName)
	}
	signerKey, err := parsePrivateKeyPEM(
		signerKeyPEM,
		signerPassphrase,
		fmt.Sprintf("%s passphrase required", signerName),
		fmt.Sprintf("invalid %s passphrase", signerName),
	)
	if err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	now := time.Now()
	dnsNames, ipAddresses := splitSANs(sans)
	// server (TLS) certs authenticate Web/API servers; client (mTLS) and
	// 802.1X (EAP-TLS) certs authenticate identity (devices/users) to a network;
	// codeSigning certs sign software.
	var extKeyUsage []x509.ExtKeyUsage
	var keyUsage x509.KeyUsage
	switch certType {
	case "client", "dot1x":
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		keyUsage = x509.KeyUsageDigitalSignature
	case "codeSigning":
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		keyUsage = x509.KeyUsageDigitalSignature
	default: // server
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   now.Add(certNotBeforeOffset),
		NotAfter:    now.AddDate(years, 0, 0),
		ExtKeyUsage: extKeyUsage,
		KeyUsage:    keyUsage,
		DNSNames:    append([]string(nil), dnsNames...),
		IPAddresses: append([]net.IP(nil), ipAddresses...),
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:    append([]string(nil), dnsNames...),
		IPAddresses: append([]net.IP(nil), ipAddresses...),
	}, key)
	if err != nil {
		return err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		return err
	}

	id := certID()
	certDir := filepath.Join(a.dataDir, "certs", id)
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		return err
	}

	if err := writePEM(filepath.Join(certDir, "csr.pem"), "CERTIFICATE REQUEST", csrDER, 0o640); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(certDir, "cert.pem"), "CERTIFICATE", certDER, 0o640); err != nil {
		return err
	}
	keyPEM, err := encodePrivateKeyPEM(key, keyPassphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}

	meta := certMetadata{
		ID:            id,
		CommonName:    commonName,
		SANs:          sans,
		Type:          certType,
		Client:        certType == "client",
		ValidityYears: years,
		CreatedAt:     now,
	}
	return a.saveCertMetadata(certDir, meta)
}

func (a *app) loadCertMetadata(certDir string) (certMetadata, error) {
	metaJSON, err := os.ReadFile(filepath.Join(certDir, "metadata.json"))
	if err != nil {
		return certMetadata{}, err
	}
	var meta certMetadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return certMetadata{}, err
	}
	meta.Type = meta.CertType()
	return meta, nil
}

func (a *app) saveCertMetadata(certDir string, meta certMetadata) error {
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(certDir, "metadata.json"), metaJSON, 0o640)
}

func (a *app) changeCAPassphrase(currentPassphrase, newPassphrase string) error {
	if err := updatePrivateKeyPassphrase(
		filepath.Join(a.dataDir, "ca-key.pem"),
		currentPassphrase,
		newPassphrase,
		"CA passphrase required",
		"invalid CA passphrase",
	); err != nil {
		return err
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errCAConfigNotFound
	}
	cfg.CAPassphraseSet = newPassphrase != ""
	return a.saveConfig(cfg)
}

func (a *app) changeIntermediatePassphrase(currentPassphrase, newPassphrase string) error {
	if err := updatePrivateKeyPassphrase(
		filepath.Join(a.dataDir, "intermediate-key.pem"),
		currentPassphrase,
		newPassphrase,
		"intermediate passphrase required",
		"invalid intermediate passphrase",
	); err != nil {
		return err
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errCAConfigNotFound
	}
	cfg.IntermediatePassphraseSet = newPassphrase != ""
	return a.saveConfig(cfg)
}

func (a *app) changeCertificatePassphrase(id, currentPassphrase, newPassphrase string) error {
	certDir, _, err := a.resolveCertificateDir(id)
	if err != nil {
		return errCertificateIDInvalid
	}
	return updatePrivateKeyPassphrase(
		filepath.Join(certDir, "key.pem"),
		currentPassphrase,
		newPassphrase,
		"certificate passphrase required",
		"invalid certificate passphrase",
	)
}

func (a *app) loadConfig() (config, bool, error) {
	path := filepath.Join(a.dataDir, "config.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config{}, false, nil
		}
		return config{}, false, err
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return config{}, false, err
	}
	return cfg, true, nil
}

func (a *app) saveConfig(cfg config) error {
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.dataDir, "config.json"), cfgJSON, 0o640)
}

func (a *app) listCerts() ([]certMetadata, error) {
	entries, err := os.ReadDir(filepath.Join(a.dataDir, "certs"))
	if err != nil {
		return nil, err
	}
	var certs []certMetadata
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(a.dataDir, "certs", entry.Name(), "metadata.json"))
		if err != nil {
			continue
		}
		var m certMetadata
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		certs = append(certs, m)
	}
	return certs, nil
}

func certID() string {
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		return fmt.Sprintf("cert-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("cert-%d-%s", time.Now().UnixNano(), hex.EncodeToString(token))
}

func writePEM(path, pemType string, der []byte, perm os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
	return os.WriteFile(path, b, perm)
}

func writeCertificateArchive(w http.ResponseWriter, certDir, safeID, dataDir, exportPassphrase string) error {
	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		return err
	}
	csrPEM, err := os.ReadFile(filepath.Join(certDir, "csr.pem"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(certDir, "key.pem"))
	if err != nil {
		return err
	}
	metadataJSON, err := os.ReadFile(filepath.Join(certDir, "metadata.json"))
	if err != nil {
		return err
	}
	caCertPEM, err := os.ReadFile(filepath.Join(dataDir, "ca-cert.pem"))
	if err != nil {
		return err
	}
	intermediateCertPEM, err := os.ReadFile(filepath.Join(dataDir, "intermediate-cert.pem"))
	hasIntermediate := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	files := map[string][]byte{
		"cert.pem":      certPEM,
		"csr.pem":       csrPEM,
		"metadata.json": metadataJSON,
		"ca-cert.pem":   caCertPEM,
	}
	if exportPassphrase != "" {
		if key, parseErr := parseUnencryptedPrivateKeyPEM(keyPEM); parseErr == nil {
			encryptedKeyPEM, encodeErr := encodePrivateKeyPEM(key, exportPassphrase)
			if encodeErr != nil {
				return encodeErr
			}
			files["key.pem"] = encryptedKeyPEM
		} else {
			return errors.New("export passphrase can only be used with unencrypted certificate keys")
		}
	} else {
		files["key.pem"] = keyPEM
	}
	keyFiles := map[string]struct{}{
		"key.pem": {},
	}
	if hasIntermediate {
		files["intermediate-cert.pem"] = intermediateCertPEM
		issuerChain := append([]byte(nil), intermediateCertPEM...)
		issuerChain = append(issuerChain, caCertPEM...)
		files["issuer-chain.pem"] = issuerChain
	} else {
		files["issuer-chain.pem"] = append([]byte(nil), caCertPEM...)
	}
	certChain := append([]byte(nil), certPEM...)
	certChain = append(certChain, files["issuer-chain.pem"]...)
	files["chain.pem"] = certChain

	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o640,
			Size: int64(len(content)),
		}
		if _, ok := keyFiles[name]; ok {
			header.Mode = 0o600
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(content); err != nil {
			return err
		}
	}

	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+safeID+".tar.gz\"")
	_, err = w.Write(archive.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// writeCertificateP12 exports a certificate as a PKCS#12 (.p12) file so it
// can be imported directly into browsers and OS keychains for mutual TLS.
func writeCertificateP12(w http.ResponseWriter, certDir, safeID, dataDir, exportPassphrase string) error {
	keyPEM, err := os.ReadFile(filepath.Join(certDir, "key.pem"))
	if err != nil {
		return err
	}
	privateKey, err := parseUnencryptedPrivateKeyPEM(keyPEM)
	if err != nil {
		return errors.New("certificate private key is encrypted: remove or disable the key passphrase before exporting a .p12")
	}

	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		return err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("certificate PEM is invalid")
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	var caCerts []*x509.Certificate
	caPEM, err := os.ReadFile(filepath.Join(dataDir, "ca-cert.pem"))
	if err == nil {
		if block, _ := pem.Decode(caPEM); block != nil {
			if caCert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				caCerts = append(caCerts, caCert)
			}
		}
	}
	if intPEM, err := os.ReadFile(filepath.Join(dataDir, "intermediate-cert.pem")); err == nil {
		if block, _ := pem.Decode(intPEM); block != nil {
			if intCert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				caCerts = append([]*x509.Certificate{intCert}, caCerts...)
			}
		}
	}

	p12Password := exportPassphrase
	if p12Password == "" {
		p12Password = pkcs12.DefaultPassword
	}
	pfxData, err := pkcs12.Modern2026.Encode(privateKey, leaf, caCerts, p12Password)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+safeID+".p12\"")
	_, err = w.Write(pfxData)
	return err
}

// caArchiveName returns the explicit list of top-level files that make up a
// whole-CA archive, in a deterministic order.
func caArchiveFiles() []string {
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

// buildCAArchive builds a tar.gz of the whole CA state (top-level files plus
// the issued certs/ tree) and returns the archived bytes.
func (a *app) buildCAArchive() ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, name := range caArchiveFiles() {
		content, err := os.ReadFile(filepath.Join(a.dataDir, name))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if err := appendTarFile(tw, name, content, 0o640); err != nil {
			return nil, err
		}
	}

	entries, err := os.ReadDir(filepath.Join(a.dataDir, "certs"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subDir := filepath.Join(a.dataDir, "certs", e.Name())
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
			if err := appendTarFile(tw, name, content, mode); err != nil {
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

func appendTarFile(tw *tar.Writer, name string, content []byte, mode os.FileMode) error {
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

// pbkdf2SHA256 derives a key from a passphrase using PBKDF2-HMAC-SHA256
// (stdlib-only implementation).
func pbkdf2SHA256(passphrase, salt []byte, iter, keyLen int) []byte {
	prf := func(password, seed []byte) []byte {
		h := hmac.New(sha256.New, password)
		h.Write(seed)
		return h.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		t := append(append([]byte(nil), salt...), buf...)
		u = prf(passphrase, t)
		t = append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			u = prf(passphrase, u)
			for j := range u {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// encryptCAArchive encrypts a tar.gz archive with a passphrase using
// AES-256-GCM with a PBKDF2-derived key. The output is tagged with a magic
// prefix so imports can detect encrypted archives.
func encryptCAArchive(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, caEncSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := pbkdf2SHA256([]byte(passphrase), salt, caEncKeyIter, caEncKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)

	out := make([]byte, 0, len(caArchiveMagic)+1+caEncSaltLen+len(nonce)+len(sealed))
	out = append(out, caArchiveMagic...)
	out = append(out, archiveCryptAESGCM)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// decryptCAArchive reverses encryptCAArchive. It returns (plain, true, nil)
// when the input was encrypted, (data, false, err) when it was not an
// encrypted archive (so callers can treat it as a plain tar.gz), and an error
// when decryption of an encrypted archive fails (e.g. wrong passphrase).
func decryptCAArchive(data []byte, passphrase string) ([]byte, bool, error) {
	if !bytes.HasPrefix(data, []byte(caArchiveMagic)) {
		return data, false, nil
	}
	rest := data[len(caArchiveMagic):]
	if len(rest) < 1+caEncSaltLen+caEncNonceLen+16 {
		return nil, false, errors.New("invalid encrypted CA archive")
	}
	mode := rest[0]
	if mode != archiveCryptAESGCM {
		return nil, false, errors.New("unsupported CA archive encryption")
	}
	rest = rest[1:]
	salt := rest[:caEncSaltLen]
	rest = rest[caEncSaltLen:]
	nonce := rest[:caEncNonceLen]
	ciphertext := rest[caEncNonceLen:]

	key := pbkdf2SHA256([]byte(passphrase), salt, caEncKeyIter, caEncKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false, errors.New("invalid CA archive passphrase or corrupted archive")
	}
	return plain, true, nil
}

// safeArchivePath validates a tar entry name and returns the corresponding
// path under base, rejecting traversal and absolute paths.
func safeArchivePath(base, name string) (string, error) {
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

// writeCAArchive streams a whole-CA archive to the response with optional
// passphrase encryption.
func (a *app) writeCAArchive(w http.ResponseWriter, exportPassphrase string) error {
	raw, err := a.buildCAArchive()
	if err != nil {
		return err
	}
	payload := raw
	if exportPassphrase != "" {
		payload, err = encryptCAArchive(raw, exportPassphrase)
		if err != nil {
			return err
		}
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"localca-ca-backup.tar.gz\"")
	_, err = w.Write(payload)
	return err
}

// importCAArchive restores a whole-CA archive (plain tar.gz or encrypted) into
// the data directory. It refuses to run when a CA already exists.
func (a *app) importCAArchive(r io.Reader, importPassphrase string) error {
	if _, hasCA, err := a.loadConfig(); err != nil {
		return err
	} else if hasCA {
		return errors.New("a CA already exists: restore into an empty data directory")
	}

	limited := io.LimitReader(r, maxImportArchive)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) >= maxImportArchive {
		return errors.New("imported archive is too large")
	}

	payload, encrypted, err := decryptCAArchive(data, importPassphrase)
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
		full, err := safeArchivePath(a.dataDir, hdr.Name)
		if err != nil {
			return err
		}
		dir := filepath.Dir(full)
		if strings.HasPrefix(full, filepath.Join(a.dataDir, "certs")) && !strings.HasSuffix(hdr.Name, "/") {
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
	}

	_, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errors.New("imported archive contains no valid configuration")
	}
	if err := a.verifyImportedCA(); err != nil {
		return err
	}
	return nil
}

func (a *app) verifyImportedCA() error {
	caPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-cert.pem"))
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

	keyPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("imported CA key missing")
	}
	caKey, err := parseUnencryptedPrivateKeyPEM(keyPEM)
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
