package ca

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// LoadTranslations reads all translation maps from the embedded i18n/*.json files.
func LoadTranslations() (map[string]map[string]string, error) {
	result := map[string]map[string]string{}
	for _, lang := range []string{"it", "en", "ja"} {
		path := filepath.Join("i18n", lang+".json")
		b, err := EmbeddedI18n.ReadFile(path)
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

func IsSupportedLanguage(lang string) bool {
	switch lang {
	case "en", "it", "ja":
		return true
	default:
		return false
	}
}

func (a *App) CurrentLanguage(cfg Config, hasCA bool) string {
	if hasCA && IsSupportedLanguage(cfg.Language) {
		return cfg.Language
	}
	if IsSupportedLanguage(a.DefaultLang) {
		return a.DefaultLang
	}
	return DefaultLanguage
}

func (a *App) Translate(lang, key string) string {
	if m, ok := a.Translations[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := a.Translations[DefaultLanguage]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

func (a *App) LoadConfig() (Config, bool, error) {
	path := filepath.Join(a.DataDir, "config.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, false, nil
		}
		return Config{}, false, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, false, err
	}
	return cfg, true, nil
}

func (a *App) SaveConfig(cfg Config) error {
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.DataDir, "config.json"), cfgJSON, 0o640)
}

func (a *App) LoadCertMetadata(certDir string) (CertMetadata, error) {
	metaJSON, err := os.ReadFile(filepath.Join(certDir, "metadata.json"))
	if err != nil {
		return CertMetadata{}, err
	}
	var meta CertMetadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return CertMetadata{}, err
	}
	meta.Type = meta.CertType()
	return meta, nil
}

func (a *App) SaveCertMetadata(certDir string, meta CertMetadata) error {
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(certDir, "metadata.json"), metaJSON, 0o640)
}

func (a *App) ListCerts() ([]CertMetadata, error) {
	entries, err := os.ReadDir(filepath.Join(a.DataDir, "certs"))
	if err != nil {
		return nil, err
	}
	var certs []CertMetadata
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(a.DataDir, "certs", entry.Name(), "metadata.json"))
		if err != nil {
			continue
		}
		var m CertMetadata
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		certs = append(certs, m)
	}
	return certs, nil
}

func (a *App) HasIntermediate() bool {
	if _, err := os.Stat(filepath.Join(a.DataDir, "intermediate-cert.pem")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(a.DataDir, "intermediate-key.pem")); err != nil {
		return false
	}
	return true
}

func (a *App) HasCRL() bool {
	_, err := os.Stat(filepath.Join(a.DataDir, "crl.pem"))
	return err == nil
}
