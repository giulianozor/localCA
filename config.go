package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// loadTranslations reads all translation maps from the embedded i18n/*.json files.
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
			return nil, err
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
