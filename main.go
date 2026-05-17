package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
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
	ID            string    `json:"id"`
	CommonName    string    `json:"common_name"`
	SANs          []string  `json:"sans"`
	ValidityYears int       `json:"validity_years"`
	CreatedAt     time.Time `json:"created_at"`
}

type pageData struct {
	HasCA                    bool
	HasIntermediate          bool
	CAYears                  int
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
	mux.HandleFunc("/intermediate/create", a.handleCreateIntermediate)
	mux.HandleFunc("/certs/create", a.handleCreateCert)
	mux.HandleFunc("/certs/delete", a.handleDeleteCert)
	mux.HandleFunc("/certs/table", a.handleCertTable)
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
	port := fs.Int("port", 8080, "porta HTTP del server web")
	lang := fs.String("lang", defaultLanguage, "lingua UI (en|it|ja)")
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
		CAYears:                  caYears,
		Config:                   cfg,
		Certificates:             certs,
		CertFilter:               filter,
		Message:                  msg,
		Error:                    errMsg,
		DefaultCertYears:         1,
		MaxCertYears:             maxCertValidityYear,
		SignerPassphraseRequired: (hasCA && cfg.CAPassphraseSet && !cfg.HasIntermediate) || (hasCA && cfg.HasIntermediate && cfg.IntermediatePassphraseSet),
		Lang:                     lang,
		T:                        a.translations[lang],
	}

	tmpl := template.Must(template.New("index").Parse(indexHTML))
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	data := pageData{
		Certificates: certs,
		T:            a.translations[lang],
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
	if cfg.HasIntermediate && a.hasIntermediate() {
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
	keyPassphrase := strings.TrimSpace(r.FormValue("key_passphrase"))
	signerPassphrase := strings.TrimSpace(r.FormValue("signer_passphrase"))
	requiresSignerPassphrase := (cfg.HasIntermediate && cfg.IntermediatePassphraseSet) || (!cfg.HasIntermediate && cfg.CAPassphraseSet)
	if requiresSignerPassphrase && signerPassphrase == "" {
		http.Redirect(w, r, "/?err="+url.QueryEscape(a.translate(lang, "msg.signer_passphrase_required")), http.StatusSeeOther)
		return
	}

	if err := a.createServerCert(commonName, sans, years, keyPassphrase, signerPassphrase); err != nil {
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

func (a *app) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	kind := r.URL.Query().Get("kind")
	id := r.URL.Query().Get("id")
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
	case "intermediate-cert-pem":
		return filepath.Join(a.dataDir, "intermediate-cert.pem"), "intermediate-cert.pem", "application/x-pem-file", nil
	case "intermediate-key-pem":
		return filepath.Join(a.dataDir, "intermediate-key.pem"), "intermediate-key.pem", "application/x-pem-file", nil
	case "intermediate-chain-pem":
		return filepath.Join(a.dataDir, "intermediate-chain.pem"), "intermediate-chain.pem", "application/x-pem-file", nil
	case "csr-pem":
		base, safeID, err := a.resolveCertificateDir(id)
		if err != nil {
			return "", "", "", err
		}
		return filepath.Join(base, "csr.pem"), safeID + "-csr.pem", "application/x-pem-file", nil
	default:
		return "", "", "", errors.New("tipo download non supportato")
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

func (a *app) hasIntermediate() bool {
	if _, err := os.Stat(filepath.Join(a.dataDir, "intermediate-cert.pem")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(a.dataDir, "intermediate-key.pem")); err != nil {
		return false
	}
	return true
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
	caKey, err := parsePrivateKeyPEM(caKeyPEM, caPassphrase, "passphrase CA richiesta", "passphrase CA non valida")
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
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(caYears, 0, 0),
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
		return errors.New("configurazione CA non trovata")
	}
	cfg.HasIntermediate = true
	cfg.IntermediateCommonName = cn
	cfg.IntermediateOrganization = org
	cfg.IntermediateCountry = country
	cfg.IntermediateValidityYears = caYears
	cfg.IntermediatePassphraseSet = passphrase != ""
	return a.saveConfig(cfg)
}

func (a *app) createServerCert(commonName string, sans []string, years int, keyPassphrase, signerPassphrase string) error {
	signerCertPEM, err := os.ReadFile(filepath.Join(a.dataDir, "ca-cert.pem"))
	if err != nil {
		return errors.New("ca non trovata")
	}
	signerName := "CA"
	signerKeyPath := filepath.Join(a.dataDir, "ca-key.pem")
	if a.hasIntermediate() {
		signerCertPEM, err = os.ReadFile(filepath.Join(a.dataDir, "intermediate-cert.pem"))
		if err != nil {
			return errors.New("intermediate-cert.pem non trovato")
		}
		signerName = "intermedia"
		signerKeyPath = filepath.Join(a.dataDir, "intermediate-key.pem")
	}
	caBlock, _ := pem.Decode(signerCertPEM)
	if caBlock == nil {
		return fmt.Errorf("certificato %s non valido", signerName)
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile(signerKeyPath)
	if err != nil {
		return fmt.Errorf("chiave %s non trovata", signerName)
	}
	caKey, err := parsePrivateKeyPEM(
		caKeyPEM,
		signerPassphrase,
		fmt.Sprintf("passphrase %s richiesta", signerName),
		fmt.Sprintf("passphrase %s non valida", signerName),
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
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.AddDate(years, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
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

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
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
		if key, parseErr := parsePrivateKeyPEM(keyPEM, "", "chiave privata protetta da passphrase", "chiave privata non valida"); parseErr == nil {
			encryptedKeyPEM, encodeErr := encodePrivateKeyPEM(key, exportPassphrase)
			if encodeErr != nil {
				return encodeErr
			}
			files["key.pem"] = encryptedKeyPEM
		} else {
			files["key.pem"] = keyPEM
		}
	} else {
		files["key.pem"] = keyPEM
	}
	var issuerChain []byte
	if hasIntermediate {
		files["intermediate-cert.pem"] = intermediateCertPEM
		issuerChain = append(append([]byte(nil), intermediateCertPEM...), caCertPEM...)
		files["issuer-chain.pem"] = issuerChain
	} else {
		issuerChain = append([]byte(nil), caCertPEM...)
		files["issuer-chain.pem"] = issuerChain
	}
	certChain := append(append([]byte(nil), certPEM...), issuerChain...)
	files["chain.pem"] = certChain

	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o640,
			Size: int64(len(content)),
		}
		if strings.HasPrefix(name, "key") {
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

func addFileToTar(tarWriter *tar.Writer, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open archive file %s: %w", path, err)
	}
	defer file.Close()

	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("copy archive file %s: %w", path, err)
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
