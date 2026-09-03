package ca

import (
	"errors"
	"time"
)

const (
	CAYears                  = 100
	IntermediateYears        = 30
	MaxCertValidityYear      = 30
	DefaultCertValidityYears = 2
	DefaultLanguage          = "en"
	CertNotBeforeOffset      = -1 * time.Hour
	CRLNextUpdateDays        = 7

	CAArchiveMagic   = "localCA-CA-ARCHIVE-V1" // magic prefix for encrypted CA archives
	CAEncKeyIter     = 210000                  // PBKDF2 iterations for CA archive encryption
	CAEncKeyLen      = 32
	CAEncSaltLen     = 16
	CAEncNonceLen    = 12
	MaxImportArchive = 512 << 20 // 512 MB cap for imported CA archives
)

const (
	ArchiveCryptNone uint8 = iota
	ArchiveCryptAESGCM
)

var (
	ErrCAConfigNotFound     = errors.New("ca configuration not found")
	ErrCertificateIDInvalid = errors.New("invalid certificate id")
)

// App is the core Certificate Authority domain object. It encapsulates the
// data directory, default language and translation maps used across the CA,
// certificate management, archive and export operations.
type App struct {
	DataDir      string
	DefaultLang  string
	Translations map[string]map[string]string
}

// Config is the persisted CA configuration.
type Config struct {
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

// CertMetadata describes an issued certificate.
type CertMetadata struct {
	ID            string     `json:"id"`
	CommonName    string     `json:"common_name"`
	SANs          []string   `json:"sans"`
	Type          string     `json:"type,omitempty"`   // server, client, dot1x, codeSigning
	Client        bool       `json:"client,omitempty"` // legacy field, kept for older metadata files
	Signer        string     `json:"signer,omitempty"` // ca or intermediate, the signer that issued this cert
	ValidityYears int        `json:"validity_years"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// SignerName returns the signer that issued the certificate, defaulting to a
// sensible choice for legacy/older metadata files that predate the Signer
// field.
func (c CertMetadata) SignerName(hasIntermediate bool) string {
	if c.Signer == "ca" {
		return "ca"
	}
	if c.Signer == "intermediate" {
		return "intermediate"
	}
	// Legacy metadata has no signer recorded: preserve the original behavior.
	if hasIntermediate {
		return "intermediate"
	}
	return "ca"
}

// CertType returns the normalized certificate type, mapping legacy metadata
// (which only tracked the Client flag) onto the current "type" values.
func (c CertMetadata) CertType() string {
	if c.Type != "" {
		return c.Type
	}
	if c.Client {
		return "client"
	}
	return "server"
}

func (c Config) SignerPassphraseRequired(hasIntermediate bool) bool {
	if hasIntermediate {
		return c.IntermediatePassphraseSet
	}
	return c.CAPassphraseSet
}

// PageData carries the data needed to render the tabbed index page.
type PageData struct {
	HasCA                    bool
	HasIntermediate          bool
	HasCRL                   bool
	CAYears                  int
	IntermediateYears        int
	Config                   Config
	Certificates             []CertMetadata
	CertFilter               string
	Message                  string
	Error                    string
	DefaultCertYears         int
	MaxCertYears             int
	SignerPassphraseRequired bool
	Lang                     string
	T                        map[string]string
}

// CertTableCtx carries the data needed to render the certificate table for a
// single certificate type inside the tabbed index page.
type CertTableCtx struct {
	T            map[string]string
	CertType     string
	Title        string
	CertFilter   string
	Certificates []CertMetadata
}

// CertTableArgs returns the rendering context for a certificate type's table,
// filtering the full certificate list down to the requested type.
func CertTableArgs(root PageData, certType, title string) CertTableCtx {
	return CertTableCtx{
		T:            root.T,
		CertType:     certType,
		Title:        title,
		CertFilter:   root.CertFilter,
		Certificates: FilterCertificatesByType(root.Certificates, certType),
	}
}
