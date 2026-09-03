package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/giulianozor/localCA/internal/ca"
)

func main() {
	dataDir, port, lang, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("usage: %s [-port 8080] [-lang en|it|ja] <data-directory>: %v", os.Args[0], err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "certs"), 0o750); err != nil {
		log.Fatalf("unable to create data directory: %v", err)
	}
	translations, err := ca.LoadTranslations()
	if err != nil {
		log.Fatalf("unable to load translations: %v", err)
	}

	a := &ca.App{DataDir: dataDir, DefaultLang: lang, Translations: translations}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handleIndex(a, w, r) })
	mux.HandleFunc("/lang", func(w http.ResponseWriter, r *http.Request) { handleSetLanguage(a, w, r) })
	mux.HandleFunc("/ca/create", func(w http.ResponseWriter, r *http.Request) { handleCreateCA(a, w, r) })
	mux.HandleFunc("/ca/import", func(w http.ResponseWriter, r *http.Request) { handleImportCA(a, w, r) })
	mux.HandleFunc("/ca/passphrase", func(w http.ResponseWriter, r *http.Request) { handleChangeCAPassphrase(a, w, r) })
	mux.HandleFunc("/ca/renew", func(w http.ResponseWriter, r *http.Request) { handleRenewCA(a, w, r) })
	mux.HandleFunc("/intermediate/create", func(w http.ResponseWriter, r *http.Request) { handleCreateIntermediate(a, w, r) })
	mux.HandleFunc("/intermediate/renew", func(w http.ResponseWriter, r *http.Request) { handleRenewIntermediate(a, w, r) })
	mux.HandleFunc("/intermediate/passphrase", func(w http.ResponseWriter, r *http.Request) { handleChangeIntermediatePassphrase(a, w, r) })
	mux.HandleFunc("/certs/create", func(w http.ResponseWriter, r *http.Request) { handleCreateCert(a, w, r) })
	mux.HandleFunc("/certs/passphrase", func(w http.ResponseWriter, r *http.Request) { handleChangeCertPassphrase(a, w, r) })
	mux.HandleFunc("/certs/revoke", func(w http.ResponseWriter, r *http.Request) { handleRevokeCert(a, w, r) })
	mux.HandleFunc("/certs/renew", func(w http.ResponseWriter, r *http.Request) { handleRenewCert(a, w, r) })
	mux.HandleFunc("/certs/delete", func(w http.ResponseWriter, r *http.Request) { handleDeleteCert(a, w, r) })
	mux.HandleFunc("/certs/table", func(w http.ResponseWriter, r *http.Request) { handleCertTable(a, w, r) })
	mux.HandleFunc("/certs/crl/generate", func(w http.ResponseWriter, r *http.Request) { handleGenerateCRL(a, w, r) })
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) { handleDownload(a, w, r) })
	mux.HandleFunc("/static/styles.css", ca.HandleStyles)
	mux.HandleFunc("/static/app.js", ca.HandleAppJS)

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
	lang := fs.String("lang", ca.DefaultLanguage, "UI language (en|it|ja)")
	if err := fs.Parse(args); err != nil {
		return "", 0, "", err
	}
	if *port < 1 || *port > 65535 {
		return "", 0, "", errors.New("invalid port: use a value between 1 and 65535")
	}
	if !ca.IsSupportedLanguage(*lang) {
		return "", 0, "", errors.New("invalid language: use en, it or ja")
	}
	remaining := fs.Args()
	if len(remaining) != 1 {
		return "", 0, "", errors.New("specify data directory path")
	}
	return remaining[0], *port, *lang, nil
}
