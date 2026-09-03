package main

import (
	"errors"
	"time"
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
