package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func (a *App) GenerateCRL(lang, signerPassphrase string) error {
	signerCertPath := filepath.Join(a.DataDir, "ca-cert.pem")
	signerKeyPath := filepath.Join(a.DataDir, "ca-key.pem")
	missingErr := a.Translate(lang, "msg.ca_passphrase_required")
	invalidErr := a.Translate(lang, "msg.ca_passphrase_invalid")
	if a.HasIntermediate() {
		signerCertPath = filepath.Join(a.DataDir, "intermediate-cert.pem")
		signerKeyPath = filepath.Join(a.DataDir, "intermediate-key.pem")
		missingErr = a.Translate(lang, "msg.intermediate_passphrase_required")
		invalidErr = a.Translate(lang, "msg.intermediate_passphrase_invalid")
	}
	signerCertPEM, err := os.ReadFile(signerCertPath)
	if err != nil {
		return errors.New(a.Translate(lang, "msg.crl_signer_cert_not_found"))
	}
	signerBlock, _ := pem.Decode(signerCertPEM)
	if signerBlock == nil {
		return errors.New(a.Translate(lang, "msg.crl_signer_cert_invalid"))
	}
	signerCert, err := x509.ParseCertificate(signerBlock.Bytes)
	if err != nil {
		return err
	}
	signerKeyPEM, err := os.ReadFile(signerKeyPath)
	if err != nil {
		return errors.New(a.Translate(lang, "msg.crl_signer_key_not_found"))
	}
	signerKey, err := ParsePrivateKeyPEM(signerKeyPEM, signerPassphrase, missingErr, invalidErr)
	if err != nil {
		return err
	}

	certs, err := a.ListCerts()
	if err != nil {
		return err
	}
	var revokedCerts []x509.RevocationListEntry
	for _, meta := range certs {
		if meta.RevokedAt == nil {
			continue
		}
		certDir := filepath.Join(a.DataDir, "certs", meta.ID)
		certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
		if err != nil {
			log.Printf("GenerateCRL: skipping cert %s: read cert.pem: %v", meta.ID, err)
			continue
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			log.Printf("GenerateCRL: skipping cert %s: no PEM block in cert.pem", meta.ID)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("GenerateCRL: skipping cert %s: parse cert.pem: %v", meta.ID, err)
			continue
		}
		revokedCerts = append(revokedCerts, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: *meta.RevokedAt,
		})
	}

	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		// NextUpdate tells CRL consumers how long this CRL is valid.
		NextUpdate:                now.AddDate(0, 0, CRLNextUpdateDays),
		RevokedCertificateEntries: revokedCerts,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, signerCert, signerKey)
	if err != nil {
		return err
	}
	if err := WritePEM(filepath.Join(a.DataDir, "crl.pem"), "X509 CRL", crlDER, 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.DataDir, "crl.der"), crlDER, 0o640)
}
