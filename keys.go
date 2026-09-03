package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func parsePrivateKeyPEM(keyPEM []byte, passphrase, missingErr, invalidErr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New(invalidErr)
	}
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if passphrase == "" {
			return nil, errors.New(missingErr)
		}
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, errors.New(invalidErr)
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New(invalidErr)
	}
	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New(invalidErr)
	}
	return rsaKey, nil
}

func parseUnencryptedPrivateKeyPEM(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || x509.IsEncryptedPEMBlock(block) {
		return nil, errors.New("private key is encrypted or invalid")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unsupported private key type")
	}
	return rsaKey, nil
}

func updatePrivateKeyPassphrase(path, currentPassphrase, newPassphrase, missingErr, invalidErr string) error {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	key, err := parsePrivateKeyPEM(keyPEM, currentPassphrase, missingErr, invalidErr)
	if err != nil {
		return err
	}
	updatedKeyPEM, err := encodePrivateKeyPEM(key, newPassphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(path, updatedKeyPEM, 0o600)
}

func encodePrivateKeyPEM(key *rsa.PrivateKey, passphrase string) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(key)
	if passphrase == "" {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

func (a *app) changeCAPassphrase(currentPassphrase, newPassphrase string) error {
	if err := updatePrivateKeyPassphrase(
		filepath.Join(a.dataDir, "ca-key.pem"),
		currentPassphrase,
		newPassphrase,
		"CA passphrase required",
		"invalid CA passphrase",
	); err != nil {
		return err
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errCAConfigNotFound
	}
	cfg.CAPassphraseSet = newPassphrase != ""
	return a.saveConfig(cfg)
}

func (a *app) changeIntermediatePassphrase(currentPassphrase, newPassphrase string) error {
	if err := updatePrivateKeyPassphrase(
		filepath.Join(a.dataDir, "intermediate-key.pem"),
		currentPassphrase,
		newPassphrase,
		"intermediate passphrase required",
		"invalid intermediate passphrase",
	); err != nil {
		return err
	}
	cfg, has, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !has {
		return errCAConfigNotFound
	}
	cfg.IntermediatePassphraseSet = newPassphrase != ""
	return a.saveConfig(cfg)
}

func (a *app) changeCertificatePassphrase(id, currentPassphrase, newPassphrase string) error {
	certDir, _, err := a.resolveCertificateDir(id)
	if err != nil {
		return errCertificateIDInvalid
	}
	return updatePrivateKeyPassphrase(
		filepath.Join(certDir, "key.pem"),
		currentPassphrase,
		newPassphrase,
		"certificate passphrase required",
		"invalid certificate passphrase",
	)
}

func certID() string {
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		return fmt.Sprintf("cert-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("cert-%d-%s", time.Now().UnixNano(), hex.EncodeToString(token))
}

func writePEM(path, pemType string, der []byte, perm os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
	return os.WriteFile(path, b, perm)
}
