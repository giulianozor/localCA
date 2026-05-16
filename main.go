package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
)

const (
	caYears             = 100
	maxCertValidityYear = 30
	defaultLanguage     = "en"
)

type app struct {
	dataDir      string
	defaultLang  string
	translations map[string]map[string]string
}

type config struct {
	CreatedAt       time.Time `json:"created_at"`
	CACommonName    string    `json:"ca_common_name"`
	Organization    string    `json:"organization"`
	Country         string    `json:"country"`
	CAValidityYears int       `json:"ca_validity_years"`
	Language        string    `json:"language"`
}

type certMetadata struct {
	ID            string    `json:"id"`
	CommonName    string    `json:"common_name"`
	SANs          []string  `json:"sans"`
	ValidityYears int       `json:"validity_years"`
	CreatedAt     time.Time `json:"created_at"`
}

type pageData struct {
	HasCA            bool
	CAYears          int
	Config           config
	Certificates     []certMetadata
	Message          string
	Error            string
	DefaultCertYears int
	MaxCertYears     int
	Lang             string
	T                map[string]string
}

func main() {
	dataDir, port, lang, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("usage: %s [-port 8080] [-lang en|it] <data-directory>: %v", os.Args[0], err)
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
	mux.HandleFunc("/certs/create", a.handleCreateCert)
	mux.HandleFunc("/download", a.handleDownload)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("localCA UI available on all interfaces (port %d), access via http://<host-ip-or-hostname>:%d", port, port)
	log.Printf("WARNING: server is reachable from network interfaces; use only in trusted networks or restrict access with firewall rules")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func parseArgs(args []string) (string, int, string, error) {
	fs := flag.NewFlagSet("localCA", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", 8080, "porta HTTP del server web")
	lang := fs.String("lang", defaultLanguage, "lingua UI (en|it)")
	if err := fs.Parse(args); err != nil {
		return "", 0, "", err
	}
	if *port < 1 || *port > 65535 {
		return "", 0, "", errors.New("invalid port: use a value between 1 and 65535")
	}
	if !isSupportedLanguage(*lang) {
		return "", 0, "", errors.New("invalid language: use en or it")
	}
	remaining := fs.Args()
	if len(remaining) != 1 {
		return "", 0, "", errors.New("specify data directory path")
	}
	return remaining[0], *port, *lang, nil
}

func loadTranslations() (map[string]map[string]string, error) {
	result := map[string]map[string]string{}
	for _, lang := range []string{"it", "en"} {
		path := filepath.Join("i18n", lang+".hson")
		b, err := os.ReadFile(path)
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
	case "en", "it":
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
	a.renderIndex(w, r.URL.Query().Get("msg"), r.URL.Query().Get("err"))
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

func (a *app) renderIndex(w http.ResponseWriter, msg, errMsg string) {
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
	lang := a.currentLanguage(cfg, hasCA)

	data := pageData{
		HasCA:            hasCA,
		CAYears:          caYears,
		Config:           cfg,
		Certificates:     certs,
		Message:          msg,
		Error:            errMsg,
		DefaultCertYears: 1,
		MaxCertYears:     maxCertValidityYear,
		Lang:             lang,
		T:                a.translations[lang],
	}

	tmpl := template.Must(template.New("index").Parse(indexHTML))
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	if err := a.createCA(cn, org, country); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.ca_created")), http.StatusSeeOther)
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

	sansInput := strings.TrimSpace(r.FormValue("sans"))
	sans, err := parseSANs(sansInput)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	commonName := strings.TrimSpace(r.FormValue("common_name"))
	if commonName == "" {
		commonName = sans[0]
	}
	years, err := parseValidityYears(r.FormValue("validity_years"))
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	if err := a.createServerCert(commonName, sans, years); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape(a.translate(lang, "msg.cert_created")), http.StatusSeeOther)
}

func (a *app) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	kind := r.URL.Query().Get("kind")
	id := r.URL.Query().Get("id")
	path, filename, ctype, err := a.resolveDownload(kind, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "file non trovato", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	_, _ = io.Copy(w, f)
}

func (a *app) resolveDownload(kind, id string) (string, string, string, error) {
	switch kind {
	case "ca-cert-pem":
		return filepath.Join(a.dataDir, "ca-cert.pem"), "ca-cert.pem", "application/x-pem-file", nil
	case "ca-cert-der":
		return filepath.Join(a.dataDir, "ca-cert.der"), "ca-cert.der", "application/pkix-cert", nil
	case "ca-key-pem":
		return filepath.Join(a.dataDir, "ca-key.pem"), "ca-key.pem", "application/x-pem-file", nil
	case "ca-key-pkcs8-pem":
		return filepath.Join(a.dataDir, "ca-key-pkcs8.pem"), "ca-key-pkcs8.pem", "application/x-pem-file", nil
	case "ca-key-der":
		return filepath.Join(a.dataDir, "ca-key.der"), "ca-key.der", "application/octet-stream", nil
	case "cert-pem", "cert-der", "chain-pem", "key-pem", "key-pkcs8-pem", "key-der":
		base, safeID, err := a.resolveCertificateDir(id)
		if err != nil {
			return "", "", "", err
		}
		switch kind {
		case "cert-pem":
			return filepath.Join(base, "cert.pem"), safeID + "-cert.pem", "application/x-pem-file", nil
		case "cert-der":
			return filepath.Join(base, "cert.der"), safeID + "-cert.der", "application/pkix-cert", nil
		case "chain-pem":
			return filepath.Join(base, "chain.pem"), safeID + "-chain.pem", "application/x-pem-file", nil
		case "key-pem":
			return filepath.Join(base, "key.pem"), safeID + "-key.pem", "application/x-pem-file", nil
		case "key-pkcs8-pem":
			return filepath.Join(base, "key-pkcs8.pem"), safeID + "-key-pkcs8.pem", "application/x-pem-file", nil
		default:
			return filepath.Join(base, "key.der"), safeID + "-key.der", "application/octet-stream", nil
		}
	default:
		return "", "", "", errors.New("tipo download non supportato")
	}
}

func (a *app) resolveCertificateDir(id string) (string, string, error) {
	if id == "" {
		return "", "", errors.New("id certificato mancante")
	}
	entries, err := os.ReadDir(filepath.Join(a.dataDir, "certs"))
	if err != nil {
		return "", "", errors.New("archivio certificati non disponibile")
	}
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() == id {
			return filepath.Join(a.dataDir, "certs", entry.Name()), entry.Name(), nil
		}
	}
	return "", "", errors.New("id certificato non valido")
}

func parseValidityYears(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 1, nil
	}
	years, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("validita non valida")
	}
	if years < 1 || years > maxCertValidityYear {
		return 0, fmt.Errorf("la validita deve essere tra 1 e %d anni", maxCertValidityYear)
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
		return nil, errors.New("inserire almeno un SAN (FQDN, IP o host .local/.locsl)")
	}
	return result, nil
}

func (a *app) createCA(cn, org, country string) error {
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
		NotBefore:             now.Add(-1 * time.Hour),
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
	if err := writePEM(filepath.Join(a.dataDir, "ca-key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey), 0o600); err != nil {
		return err
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(a.dataDir, "ca-key-pkcs8.pem"), "PRIVATE KEY", pkcs8Bytes, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.dataDir, "ca-key.der"), x509.MarshalPKCS1PrivateKey(privateKey), 0o600); err != nil {
		return err
	}

	cfg := config{
		CreatedAt:       now,
		CACommonName:    cn,
		Organization:    org,
		Country:         country,
		CAValidityYears: caYears,
		Language:        a.defaultLang,
	}
	return a.saveConfig(cfg)
}

func (a *app) createServerCert(commonName string, sans []string, years int) error {
	caCertPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-cert.pem"))
	if err != nil {
		return errors.New("ca non trovata")
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return errors.New("ca-cert.pem non valido")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("chiave CA non trovata")
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return errors.New("ca-key.pem non valido")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.AddDate(years, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, san)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}

	id := certID()
	certDir := filepath.Join(a.dataDir, "certs", id)
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		return err
	}

	if err := writePEM(filepath.Join(certDir, "cert.pem"), "CERTIFICATE", certDER, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "cert.der"), certDER, 0o640); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(certDir, "key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600); err != nil {
		return err
	}
	keyPKCS8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(certDir, "key-pkcs8.pem"), "PRIVATE KEY", keyPKCS8, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.der"), x509.MarshalPKCS1PrivateKey(key), 0o600); err != nil {
		return err
	}
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chainPEM = append(chainPEM, caCertPEM...)
	if err := os.WriteFile(filepath.Join(certDir, "chain.pem"), chainPEM, 0o640); err != nil {
		return err
	}

	meta := certMetadata{
		ID:            id,
		CommonName:    commonName,
		SANs:          sans,
		ValidityYears: years,
		CreatedAt:     now,
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(certDir, "metadata.json"), metaJSON, 0o640)
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

const indexHTML = `<!doctype html>
<html lang="{{.Lang}}">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>localCA</title>
  <style>
    :root { color-scheme: dark; }
    body { background: #111827; color: #e5e7eb; font-family: Inter, system-ui, sans-serif; margin: 0; }
    .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
    .card { background: #1f2937; border: 1px solid #374151; border-radius: 10px; padding: 18px; margin-bottom: 16px; }
    h1,h2 { margin-top: 0; }
    label { display: block; margin-top: 10px; font-size: 0.95rem; }
    input,select { width: 100%; padding: 8px; background: #111827; color: #e5e7eb; border: 1px solid #4b5563; border-radius: 6px; margin-top: 4px; }
    button { margin-top: 12px; background: #2563eb; color: white; border: none; border-radius: 6px; padding: 10px 14px; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #374151; text-align: left; padding: 8px; vertical-align: top; }
    a { color: #93c5fd; }
    .msg { background: #064e3b; border: 1px solid #10b981; color: #d1fae5; padding: 10px; border-radius: 6px; margin-bottom: 12px; }
    .err { background: #7f1d1d; border: 1px solid #f87171; color: #fee2e2; padding: 10px; border-radius: 6px; margin-bottom: 12px; }
    .muted { color: #9ca3af; font-size: 0.9rem; }
    .lang-form { max-width: 280px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>localCA</h1>
    <p class="muted">{{index .T "subtitle"}}</p>

    <div class="card lang-form">
      <h2>{{index .T "language.title"}}</h2>
      <form method="post" action="/lang">
        <label>{{index .T "language.label"}}
          <select name="lang">
            <option value="en" {{if eq .Lang "en"}}selected{{end}}>{{index .T "language.en"}}</option>
            <option value="it" {{if eq .Lang "it"}}selected{{end}}>{{index .T "language.it"}}</option>
          </select>
        </label>
        <button type="submit">{{index .T "language.button"}}</button>
      </form>
    </div>

    {{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}

    {{if not .HasCA}}
      <div class="card">
        <h2>{{index .T "ca.create.title"}}</h2>
        <p class="muted">{{printf (index .T "ca.create.validity") .CAYears}}</p>
        <form method="post" action="/ca/create">
          <label>{{index .T "ca.create.cn_label"}}<input name="ca_common_name" placeholder="{{index .T "ca.create.cn_placeholder"}}"></label>
          <label>{{index .T "ca.create.org_label"}}<input name="organization" placeholder="{{index .T "ca.create.org_placeholder"}}"></label>
          <label>{{index .T "ca.create.country_label"}}<input name="country" placeholder="{{index .T "ca.create.country_placeholder"}}"></label>
          <button type="submit">{{index .T "ca.create.button"}}</button>
        </form>
      </div>
    {{else}}
      <div class="card">
        <h2>{{index .T "ca.active.title"}}</h2>
        <p><strong>{{index .T "ca.active.cn"}}:</strong> {{.Config.CACommonName}}<br>
           <strong>{{index .T "ca.active.org"}}:</strong> {{.Config.Organization}}<br>
           <strong>{{index .T "ca.active.country"}}:</strong> {{.Config.Country}}<br>
           <strong>{{index .T "ca.active.validity"}}:</strong> {{printf (index .T "years.value") .Config.CAValidityYears}}</p>
        <p>{{index .T "export.label"}}: <a href="/download?kind=ca-cert-pem">CA cert PEM</a> · <a href="/download?kind=ca-cert-der">CA cert DER</a> · <a href="/download?kind=ca-key-pem">CA key PEM</a> · <a href="/download?kind=ca-key-pkcs8-pem">CA key PKCS8 PEM</a> · <a href="/download?kind=ca-key-der">CA key DER</a></p>
      </div>

      <div class="card">
        <h2>{{index .T "cert.create.title"}}</h2>
        <form method="post" action="/certs/create">
          <label>{{index .T "cert.create.cn_label"}}<input name="common_name" placeholder="dev.local"></label>
          <label>{{index .T "cert.create.sans_label"}}
            <input name="sans" placeholder="dev.local, api.locsl, 127.0.0.1">
          </label>
          <label>{{printf (index .T "cert.create.validity_label") .MaxCertYears .DefaultCertYears}}
            <input name="validity_years" type="number" min="1" max="{{.MaxCertYears}}" value="{{.DefaultCertYears}}">
          </label>
          <button type="submit">{{index .T "cert.create.button"}}</button>
        </form>
      </div>

      <div class="card">
        <h2>{{index .T "cert.list.title"}}</h2>
        <table>
          <thead><tr><th>ID</th><th>CN</th><th>SAN</th><th>{{index .T "cert.list.validity"}}</th><th>{{index .T "cert.list.export"}}</th></tr></thead>
          <tbody>
            {{range .Certificates}}
              <tr>
                <td>{{.ID}}</td>
                <td>{{.CommonName}}</td>
                <td>{{range $i, $v := .SANs}}{{if $i}}, {{end}}{{$v}}{{end}}</td>
                <td>{{printf (index $.T "years.value") .ValidityYears}}</td>
                <td>
                  <a href="/download?kind=cert-pem&id={{.ID}}">cert PEM</a> ·
                  <a href="/download?kind=cert-der&id={{.ID}}">cert DER</a> ·
                  <a href="/download?kind=chain-pem&id={{.ID}}">chain PEM</a> ·
                  <a href="/download?kind=key-pem&id={{.ID}}">key PEM</a> ·
                  <a href="/download?kind=key-pkcs8-pem&id={{.ID}}">key PKCS8 PEM</a> ·
                  <a href="/download?kind=key-der&id={{.ID}}">key DER</a>
                </td>
              </tr>
            {{else}}
              <tr><td colspan="5" class="muted">{{index .T "cert.list.none"}}</td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
    {{end}}
  </div>
</body>
</html>`
