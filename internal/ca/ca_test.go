package ca

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseValidityYears(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{name: "default", input: "", want: DefaultCertValidityYears},
		{name: "valid", input: "30", want: 30},
		{name: "too high", input: "31", wantErr: true},
		{name: "invalid", input: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseValidityYears(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseValidityYears() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("ParseValidityYears() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSANs(t *testing.T) {
	t.Run("valid and deduplicated", func(t *testing.T) {
		got, err := ParseSANs("Dev.Local, 127.0.0.1, other.local")
		if err != nil {
			t.Fatalf("ParseSANs() error = %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("ParseSANs() len = %d, want 3", len(got))
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := ParseSANs("   ,   "); err == nil {
			t.Fatal("ParseSANs() expected error")
		}
	})
}

func TestResolveCertificateDir(t *testing.T) {
	tempDir := t.TempDir()
	a := &App{DataDir: tempDir}
	if err := os.MkdirAll(filepath.Join(tempDir, "certs", "cert-1"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	gotPath, gotID, err := a.ResolveCertificateDir("cert-1")
	if err != nil {
		t.Fatalf("ResolveCertificateDir() error = %v", err)
	}
	if gotID != "cert-1" {
		t.Fatalf("ResolveCertificateDir() id = %s, want cert-1", gotID)
	}
	wantPath := filepath.Join(tempDir, "certs", "cert-1")
	if gotPath != wantPath {
		t.Fatalf("ResolveCertificateDir() path = %s, want %s", gotPath, wantPath)
	}

	if _, _, err := a.ResolveCertificateDir("../cert-1"); err == nil {
		t.Fatal("ResolveCertificateDir() expected error for invalid id")
	}
}

func TestLoadTranslationsUsesEmbeddedAssets(t *testing.T) {
	translations, err := LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	if got := translations["en"]["language.label"]; got != "Select language" {
		t.Fatalf("translations[en][language.label] = %q, want %q", got, "Select language")
	}
	if got := translations["ja"]["cert.create.button"]; got != "証明書を作成" {
		t.Fatalf("translations[ja][cert.create.button] = %q, want %q", got, "証明書を作成")
	}
}

func TestFilterCertificates(t *testing.T) {
	certs := []CertMetadata{
		{ID: "cert-1", CommonName: "dev.local", SANs: []string{"dev.local", "127.0.0.1"}, CreatedAt: time.Now()},
		{ID: "cert-2", CommonName: "api.local", SANs: []string{"api.local"}, CreatedAt: time.Now()},
	}

	t.Run("empty query returns all", func(t *testing.T) {
		got := FilterCertificates(certs, "")
		if !reflect.DeepEqual(got, certs) {
			t.Fatalf("FilterCertificates() = %#v, want %#v", got, certs)
		}
	})

	t.Run("filter by common name", func(t *testing.T) {
		got := FilterCertificates(certs, "api")
		if len(got) != 1 || got[0].ID != "cert-2" {
			t.Fatalf("FilterCertificates() got %#v, want cert-2 only", got)
		}
	})

	t.Run("filter by SAN case insensitive", func(t *testing.T) {
		got := FilterCertificates(certs, "DEV.LOCAL")
		if len(got) != 1 || got[0].ID != "cert-1" {
			t.Fatalf("FilterCertificates() got %#v, want cert-1 only", got)
		}
	})
}

func TestCreateServerCertSavesCSRAndSeparatesIPSANs(t *testing.T) {
	a, certID := createTestCertificate(t)
	certDir := filepath.Join(a.DataDir, "certs", certID)

	cert := parseCertificatePEM(t, filepath.Join(certDir, "cert.pem"))
	if !reflect.DeepEqual(cert.DNSNames, []string{"myserver.example.com", "myserver.internal"}) {
		t.Fatalf("certificate DNSNames = %#v, want %#v", cert.DNSNames, []string{"myserver.example.com", "myserver.internal"})
	}
	assertIPAddresses(t, cert.IPAddresses, []string{"192.168.1.100", "10.0.0.50", "127.0.0.1"})

	csrPEM, err := os.ReadFile(filepath.Join(certDir, "csr.pem"))
	if err != nil {
		t.Fatalf("read csr.pem: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("csr.pem did not contain a PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest() error = %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature() error = %v", err)
	}
	if !reflect.DeepEqual(csr.DNSNames, []string{"myserver.example.com", "myserver.internal"}) {
		t.Fatalf("CSR DNSNames = %#v, want %#v", csr.DNSNames, []string{"myserver.example.com", "myserver.internal"})
	}
	assertIPAddresses(t, csr.IPAddresses, []string{"192.168.1.100", "10.0.0.50", "127.0.0.1"})
}

func TestCreateServerCertUsesIntermediateAsIssuer(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}
	if err := a.CreateServerCert("leaf.local", []string{"leaf.local"}, 1, "", "", a.HasIntermediate(), "server"); err != nil {
		t.Fatalf("CreateServerCert() error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("ListCerts() len = %d, want 1", len(certs))
	}
	cert := parseCertificatePEM(t, filepath.Join(tempDir, "certs", certs[0].ID, "cert.pem"))
	intermediate := parseCertificatePEM(t, filepath.Join(tempDir, "intermediate-cert.pem"))
	if cert.Issuer.CommonName != intermediate.Subject.CommonName {
		t.Fatalf("leaf issuer CN = %q, want %q", cert.Issuer.CommonName, intermediate.Subject.CommonName)
	}
}

func TestCreateServerCertRequiresSignerPassphrase(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", "root-pass"); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("leaf.local", []string{"leaf.local"}, 1, "", "", a.HasIntermediate(), "server"); err == nil {
		t.Fatal("CreateServerCert() expected error when signer passphrase is missing")
	}
	if err := a.CreateServerCert("leaf.local", []string{"leaf.local"}, 1, "", "root-pass", a.HasIntermediate(), "server"); err != nil {
		t.Fatalf("CreateServerCert() with signer passphrase error = %v", err)
	}
}

func TestCreateIntermediateCAUsesDefaultValidityYears(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}
	cfg, has, err := a.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if !has {
		t.Fatal("LoadConfig() expected config to exist")
	}
	if cfg.IntermediateValidityYears != IntermediateYears {
		t.Fatalf("IntermediateValidityYears = %d, want %d", cfg.IntermediateValidityYears, IntermediateYears)
	}
}

func TestChangeCAPassphraseSetAndRemove(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", "initial-pass"); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.ChangeCAPassphrase("initial-pass", "new-pass"); err != nil {
		t.Fatalf("ChangeCAPassphrase(set) error = %v", err)
	}
	if err := a.CreateServerCert("with-new-pass.local", []string{"with-new-pass.local"}, 1, "", "new-pass", a.HasIntermediate(), "server"); err != nil {
		t.Fatalf("CreateServerCert() with new signer passphrase error = %v", err)
	}
	if err := a.ChangeCAPassphrase("new-pass", ""); err != nil {
		t.Fatalf("ChangeCAPassphrase(remove) error = %v", err)
	}
	if err := a.CreateServerCert("without-pass.local", []string{"without-pass.local"}, 1, "", "", a.HasIntermediate(), "server"); err != nil {
		t.Fatalf("CreateServerCert() without signer passphrase error = %v", err)
	}
}

func TestRenewCASameSubjectNewSerial(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	origCert := parseCertificatePEM(t, filepath.Join(tempDir, "ca-cert.pem"))

	if err := a.RenewCA(""); err != nil {
		t.Fatalf("RenewCA() error = %v", err)
	}

	newCert := parseCertificatePEM(t, filepath.Join(tempDir, "ca-cert.pem"))
	if newCert.SerialNumber.Cmp(origCert.SerialNumber) == 0 {
		t.Fatal("RenewCA() serial should change")
	}
	if newCert.Subject.CommonName != origCert.Subject.CommonName {
		t.Fatalf("RenewCA() CN = %q, want %q", newCert.Subject.CommonName, origCert.Subject.CommonName)
	}
	if newCert.NotAfter.Before(time.Now().AddDate(CAYears-1, 0, 0)) {
		t.Fatal("RenewCA() validity too short")
	}
	if !newCert.IsCA {
		t.Fatal("RenewCA() cert should have CA flag")
	}
}

func TestRenewCAWithPassphrase(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", "secret"); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.RenewCA("secret"); err != nil {
		t.Fatalf("RenewCA() with passphrase error = %v", err)
	}
	if err := a.RenewCA(""); err == nil {
		t.Fatal("RenewCA() expected error with missing passphrase")
	}
}

func TestRenewIntermediateCAWithoutIntermediateFails(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.RenewIntermediateCA(""); err == nil {
		t.Fatal("RenewIntermediateCA() expected error when no intermediate exists")
	}
}

func TestCreateServerCertRejectsInvalidValidity(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	for _, years := range []int{0, -1, MaxCertValidityYear + 1} {
		if err := a.CreateServerCert("bad.local", []string{"bad.local"}, years, "", "", false, "server"); err == nil {
			t.Fatalf("CreateServerCert() with years=%d succeeded, want error", years)
		}
	}
}

func TestRenewCARegeneratesIntermediateChain(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	if err := a.RenewCA(""); err != nil {
		t.Fatalf("RenewCA() error = %v", err)
	}

	// The second block in intermediate-chain.pem must be the renewed root.
	newCA := parseCertificatePEM(t, filepath.Join(tempDir, "ca-cert.pem"))
	chainPEM, err := os.ReadFile(filepath.Join(tempDir, "intermediate-chain.pem"))
	if err != nil {
		t.Fatalf("read intermediate-chain.pem: %v", err)
	}
	blocks := pemBlockList(t, chainPEM)
	if len(blocks) < 2 {
		t.Fatalf("intermediate-chain.pem should have 2 blocks, got %d", len(blocks))
	}
	root, err := x509.ParseCertificate(blocks[1])
	if err != nil {
		t.Fatalf("parse chain root: %v", err)
	}
	if root.SerialNumber.Cmp(newCA.SerialNumber) != 0 {
		t.Fatal("intermediate-chain.pem root cert is stale after RenewCA")
	}
}

func pemBlockList(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var out [][]byte
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		out = append(out, block.Bytes)
		rest = remaining
	}
	return out
}

func TestCAIntermediateAndSignerChoice(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}

	t.Run("renew intermediate creates new cert signed by CA", func(t *testing.T) {
		origInt := parseCertificatePEM(t, filepath.Join(tempDir, "intermediate-cert.pem"))

		if err := a.RenewIntermediateCA(""); err != nil {
			t.Fatalf("RenewIntermediateCA() error = %v", err)
		}

		newInt := parseCertificatePEM(t, filepath.Join(tempDir, "intermediate-cert.pem"))
		if newInt.SerialNumber.Cmp(origInt.SerialNumber) == 0 {
			t.Fatal("serial should change")
		}
		if newInt.Subject.CommonName != origInt.Subject.CommonName {
			t.Fatalf("CN = %q, want %q", newInt.Subject.CommonName, origInt.Subject.CommonName)
		}
		if newInt.Issuer.CommonName != "Test Root" {
			t.Fatalf("issuer = %q, want 'Test Root'", newInt.Issuer.CommonName)
		}
		if !newInt.IsCA {
			t.Fatal("cert should have CA flag")
		}

		chainPEM, err := os.ReadFile(filepath.Join(tempDir, "intermediate-chain.pem"))
		if err != nil {
			t.Fatalf("read intermediate-chain.pem: %v", err)
		}
		block, _ := pem.Decode(chainPEM)
		if block == nil {
			t.Fatal("intermediate-chain.pem has no first block")
		}
		chainInt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse first chain cert: %v", err)
		}
		if chainInt.SerialNumber.Cmp(newInt.SerialNumber) != 0 {
			t.Fatal("intermediate-chain.pem first cert serial does not match renewed cert")
		}
	})

	t.Run("signer choice: false signs with CA, true signs with intermediate", func(t *testing.T) {
		if err := a.CreateServerCert("ca-signed.local", []string{"ca-signed.local"}, 1, "", "", false, "server"); err != nil {
			t.Fatalf("CreateServerCert(useIntermediate=false) error = %v", err)
		}
		if err := a.CreateServerCert("int-signed.local", []string{"int-signed.local"}, 1, "", "", true, "server"); err != nil {
			t.Fatalf("CreateServerCert(useIntermediate=true) error = %v", err)
		}

		certs, err := a.ListCerts()
		if err != nil {
			t.Fatalf("ListCerts() error = %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("ListCerts() len = %d, want 2", len(certs))
		}

		caCert := parseCertificatePEM(t, filepath.Join(tempDir, "ca-cert.pem"))
		intCert := parseCertificatePEM(t, filepath.Join(tempDir, "intermediate-cert.pem"))

		for _, meta := range certs {
			cert := parseCertificatePEM(t, filepath.Join(tempDir, "certs", meta.ID, "cert.pem"))
			switch meta.CommonName {
			case "ca-signed.local":
				if cert.Issuer.CommonName != caCert.Subject.CommonName {
					t.Fatalf("ca-signed.local issuer = %q, want %q", cert.Issuer.CommonName, caCert.Subject.CommonName)
				}
			case "int-signed.local":
				if cert.Issuer.CommonName != intCert.Subject.CommonName {
					t.Fatalf("int-signed.local issuer = %q, want %q", cert.Issuer.CommonName, intCert.Subject.CommonName)
				}
			}
		}
	})
}

func TestGenerateCRL(t *testing.T) {
	translations, err := LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	a, certID := createTestCertificate(t)
	a.Translations = translations

	// Revoke the certificate
	now := time.Now()
	certDir := filepath.Join(a.DataDir, "certs", certID)
	meta, err := a.LoadCertMetadata(certDir)
	if err != nil {
		t.Fatalf("LoadCertMetadata() error = %v", err)
	}
	meta.RevokedAt = &now
	if err := a.SaveCertMetadata(certDir, meta); err != nil {
		t.Fatalf("SaveCertMetadata() error = %v", err)
	}

	// Generate CRL
	if err := a.GenerateCRL("en", ""); err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Verify crl.pem exists and is parseable
	crlPEM, err := os.ReadFile(filepath.Join(a.DataDir, "crl.pem"))
	if err != nil {
		t.Fatalf("read crl.pem error = %v", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("crl.pem has no PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList() error = %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL entries = %d, want 1", len(crl.RevokedCertificateEntries))
	}

	// Verify crl.der exists
	crlDER, err := os.ReadFile(filepath.Join(a.DataDir, "crl.der"))
	if err != nil {
		t.Fatalf("read crl.der error = %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("crl.der is empty")
	}

	// Verify the serial in the CRL matches the revoked cert
	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		t.Fatalf("read cert.pem error = %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("cert.pem has no PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("CRL entry serial = %s, want %s",
			crl.RevokedCertificateEntries[0].SerialNumber,
			cert.SerialNumber)
	}
}

func TestGenerateCRLOnlyListsCertsForItsSigner(t *testing.T) {
	translations, err := LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	a := &App{DataDir: t.TempDir(), DefaultLang: "en", Translations: translations}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	// Root-signed leaf (created before the intermediate).
	if err := a.CreateServerCert("root-signed.local", []string{"root-signed.local"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("CreateServerCert(root-signed) error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}
	// Intermediate-signed leaf.
	if err := a.CreateServerCert("int-signed.local", []string{"int-signed.local"}, 1, "", "", true, "server"); err != nil {
		t.Fatalf("CreateServerCert(int-signed) error = %v", err)
	}

	allCerts, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(allCerts) != 2 {
		t.Fatalf("ListCerts() len = %d, want 2", len(allCerts))
	}
	// Revoke both leaves.
	revoke := map[string]bool{}
	for _, c := range allCerts {
		certDir := filepath.Join(a.DataDir, "certs", c.ID)
		m, err := a.LoadCertMetadata(certDir)
		if err != nil {
			t.Fatalf("LoadCertMetadata(%s) error = %v", c.ID, err)
		}
		now := time.Now()
		m.RevokedAt = &now
		if err := a.SaveCertMetadata(certDir, m); err != nil {
			t.Fatalf("SaveCertMetadata(%s) error = %v", c.ID, err)
		}
		revoke[c.ID] = true
	}

	// CRL is signed by the default signer: the intermediate, since it exists.
	if err := a.GenerateCRL("en", ""); err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}
	crlPEM, err := os.ReadFile(filepath.Join(a.DataDir, "crl.pem"))
	if err != nil {
		t.Fatalf("read crl.pem error = %v", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("crl.pem has no PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList() error = %v", err)
	}

	want := 1 // only the intermediate-signed leaf belongs to the intermediate CRL
	if got := len(crl.RevokedCertificateEntries); got != want {
		t.Fatalf("CRL serials = %d, want %d (the root-signed leaf must not be in the intermediate-signed CRL)", got, want)
	}
	for _, c := range allCerts {
		certDir := filepath.Join(a.DataDir, "certs", c.ID)
		cert := parseCertificatePEM(t, filepath.Join(certDir, "cert.pem"))
		found := false
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				found = true
				break
			}
		}
		if c.Signer == "intermediate" && !found {
			t.Fatalf("intermediate-signed cert serial missing from its CRL")
		}
		if c.Signer == "ca" && found {
			t.Fatalf("root-signed cert serial must not appear in the intermediate-signed CRL")
		}
	}
}

func createTestCertificate(t *testing.T) (*App, string) {
	t.Helper()

	tempDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tempDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	a := &App{DataDir: tempDir, DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("myserver.example.com", []string{
		"myserver.example.com",
		"myserver.internal",
		"192.168.1.100",
		"10.0.0.50",
		"127.0.0.1",
	}, 1, "", "", a.HasIntermediate(), "server"); err != nil {
		t.Fatalf("CreateServerCert() error = %v", err)
	}
	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("ListCerts() len = %d, want 1", len(certs))
	}
	return a, certs[0].ID
}

func parseCertificatePEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s did not contain a PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%s) error = %v", path, err)
	}
	return cert
}

func assertIPAddresses(t *testing.T, got []net.IP, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("IPAddresses len = %d, want %d", len(got), len(want))
	}
	for i, expected := range want {
		if got[i].String() != expected {
			t.Fatalf("IPAddresses[%d] = %s, want %s", i, got[i], expected)
		}
	}
}
