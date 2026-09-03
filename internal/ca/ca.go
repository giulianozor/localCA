package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func (a *App) CreateCA(cn, org, country, passphrase string) error {
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
		NotBefore:             now.Add(CertNotBeforeOffset),
		NotAfter:              now.AddDate(CAYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	if err := WritePEM(filepath.Join(a.DataDir, "ca-cert.pem"), "CERTIFICATE", der, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.DataDir, "ca-cert.der"), der, 0o640); err != nil {
		return err
	}
	keyPEM, err := EncodePrivateKeyPEM(privateKey, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.DataDir, "ca-key.pem"), keyPEM, 0o600); err != nil {
		return err
	}

	cfg := Config{
		CreatedAt:       now,
		CACommonName:    cn,
		Organization:    org,
		Country:         country,
		CAValidityYears: CAYears,
		Language:        a.DefaultLang,
		CAPassphraseSet: passphrase != "",
	}
	return a.SaveConfig(cfg)
}

func (a *App) CreateIntermediateCA(cn, org, country, caPassphrase, passphrase string) error {
	caCertPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-cert.pem"))
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
	caKeyPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("CA key not found")
	}
	caKey, err := ParsePrivateKeyPEM(caKeyPEM, caPassphrase, "CA passphrase required", "invalid CA passphrase")
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
		NotBefore:             now.Add(CertNotBeforeOffset),
		NotAfter:              now.AddDate(IntermediateYears, 0, 0),
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
	if err := WritePEM(filepath.Join(a.DataDir, "intermediate-cert.pem"), "CERTIFICATE", certDER, 0o640); err != nil {
		return err
	}
	keyPEM, err := EncodePrivateKeyPEM(key, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.DataDir, "intermediate-key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chain = append(chain, caCertPEM...)
	if err := os.WriteFile(filepath.Join(a.DataDir, "intermediate-chain.pem"), chain, 0o640); err != nil {
		return err
	}
	cfg, has, err := a.LoadConfig()
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
	cfg.IntermediateValidityYears = IntermediateYears
	cfg.IntermediatePassphraseSet = passphrase != ""
	return a.SaveConfig(cfg)
}

func (a *App) RenewCA(caPassphrase string) error {
	cfg, has, err := a.LoadConfig()
	if err != nil {
		return err
	}
	if !has {
		return ErrCAConfigNotFound
	}

	caKeyPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("CA key not found")
	}
	caKey, err := ParsePrivateKeyPEM(caKeyPEM, caPassphrase, "CA passphrase required", "invalid CA passphrase")
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
		NotBefore:             now.Add(CertNotBeforeOffset),
		NotAfter:              now.AddDate(CAYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	if err := WritePEM(filepath.Join(a.DataDir, "ca-cert.pem"), "CERTIFICATE", der, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.DataDir, "ca-cert.der"), der, 0o640); err != nil {
		return err
	}
	return nil
}

func (a *App) RenewIntermediateCA(caPassphrase string) error {
	cfg, has, err := a.LoadConfig()
	if err != nil {
		return err
	}
	if !has {
		return ErrCAConfigNotFound
	}
	if !a.HasIntermediate() {
		return errors.New("no intermediate certificate to renew")
	}

	caCertPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-cert.pem"))
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

	caKeyPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-key.pem"))
	if err != nil {
		return errors.New("CA key not found")
	}
	caKey, err := ParsePrivateKeyPEM(caKeyPEM, caPassphrase, "CA passphrase required", "invalid CA passphrase")
	if err != nil {
		return err
	}

	intCertPEM, err := os.ReadFile(filepath.Join(a.DataDir, "intermediate-cert.pem"))
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
		NotBefore:             now.Add(CertNotBeforeOffset),
		NotAfter:              now.AddDate(IntermediateYears, 0, 0),
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

	if err := WritePEM(filepath.Join(a.DataDir, "intermediate-cert.pem"), "CERTIFICATE", certDER, 0o640); err != nil {
		return err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chain = append(chain, caCertPEM...)
	if err := os.WriteFile(filepath.Join(a.DataDir, "intermediate-chain.pem"), chain, 0o640); err != nil {
		return err
	}
	return nil
}
