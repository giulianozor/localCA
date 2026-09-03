package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func (a *App) CreateServerCert(commonName string, sans []string, years int, keyPassphrase, signerPassphrase string, useIntermediate bool, certType string) error {
	signerCertPEM, err := os.ReadFile(filepath.Join(a.DataDir, "ca-cert.pem"))
	if err != nil {
		return errors.New("CA certificate not found")
	}
	signerName := "CA"
	signerKeyPath := filepath.Join(a.DataDir, "ca-key.pem")
	if useIntermediate {
		signerCertPEM, err = os.ReadFile(filepath.Join(a.DataDir, "intermediate-cert.pem"))
		if err != nil {
			return errors.New("intermediate certificate not found")
		}
		signerName = "intermediate"
		signerKeyPath = filepath.Join(a.DataDir, "intermediate-key.pem")
	}
	signerBlock, _ := pem.Decode(signerCertPEM)
	if signerBlock == nil {
		return fmt.Errorf("invalid %s certificate PEM", signerName)
	}
	signerCert, err := x509.ParseCertificate(signerBlock.Bytes)
	if err != nil {
		return err
	}

	signerKeyPEM, err := os.ReadFile(signerKeyPath)
	if err != nil {
		return fmt.Errorf("%s key not found", signerName)
	}
	signerKey, err := ParsePrivateKeyPEM(
		signerKeyPEM,
		signerPassphrase,
		fmt.Sprintf("%s passphrase required", signerName),
		fmt.Sprintf("invalid %s passphrase", signerName),
	)
	if err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	now := time.Now()
	dnsNames, ipAddresses := SplitSANs(sans)
	serial, err := randomSerialNumber()
	if err != nil {
		return err
	}
	// server (TLS) certs authenticate Web/API servers; client (mTLS) and
	// 802.1X (EAP-TLS) certs authenticate identity (devices/users) to a network;
	// codeSigning certs sign software.
	var extKeyUsage []x509.ExtKeyUsage
	var keyUsage x509.KeyUsage
	switch certType {
	case "client", "dot1x":
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		keyUsage = x509.KeyUsageDigitalSignature
	case "codeSigning":
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		keyUsage = x509.KeyUsageDigitalSignature
	default: // server
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   now.Add(CertNotBeforeOffset),
		NotAfter:    now.AddDate(years, 0, 0),
		ExtKeyUsage: extKeyUsage,
		KeyUsage:    keyUsage,
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

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		return err
	}

	id := CertID()
	certDir := filepath.Join(a.DataDir, "certs", id)
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		return err
	}

	if err := WritePEM(filepath.Join(certDir, "csr.pem"), "CERTIFICATE REQUEST", csrDER, 0o640); err != nil {
		return err
	}
	if err := WritePEM(filepath.Join(certDir, "cert.pem"), "CERTIFICATE", certDER, 0o640); err != nil {
		return err
	}
	keyPEM, err := EncodePrivateKeyPEM(key, keyPassphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}

	meta := CertMetadata{
		ID:            id,
		CommonName:    commonName,
		SANs:          sans,
		Type:          certType,
		Client:        certType == "client",
		ValidityYears: years,
		CreatedAt:     now,
	}
	return a.SaveCertMetadata(certDir, meta)
}
