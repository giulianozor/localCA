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
)

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
