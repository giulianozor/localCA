package ca

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// pbkdf2SHA256 derives a key from a passphrase using PBKDF2-HMAC-SHA256
// (stdlib-only implementation).
func pbkdf2SHA256(passphrase, salt []byte, iter, keyLen int) []byte {
	prf := func(password, seed []byte) []byte {
		h := hmac.New(sha256.New, password)
		h.Write(seed)
		return h.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		t := append(append([]byte(nil), salt...), buf...)
		u = prf(passphrase, t)
		t = append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			u = prf(passphrase, u)
			for j := range u {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// EncryptCAArchive encrypts a tar.gz archive with a passphrase using
// AES-256-GCM with a PBKDF2-derived key. The output is tagged with a magic
// prefix so imports can detect encrypted archives.
func EncryptCAArchive(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, CAEncSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := pbkdf2SHA256([]byte(passphrase), salt, CAEncKeyIter, CAEncKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)

	out := make([]byte, 0, len(CAArchiveMagic)+1+CAEncSaltLen+len(nonce)+len(sealed))
	out = append(out, CAArchiveMagic...)
	out = append(out, ArchiveCryptAESGCM)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// DecryptCAArchive reverses EncryptCAArchive. It returns (plain, true, nil)
// when the input was encrypted, (data, false, err) when it was not an
// encrypted archive (so callers can treat it as a plain tar.gz), and an error
// when decryption of an encrypted archive fails (e.g. wrong passphrase).
func DecryptCAArchive(data []byte, passphrase string) ([]byte, bool, error) {
	if !bytes.HasPrefix(data, []byte(CAArchiveMagic)) {
		return data, false, nil
	}
	rest := data[len(CAArchiveMagic):]
	if len(rest) < 1+CAEncSaltLen+CAEncNonceLen+16 {
		return nil, false, errors.New("invalid encrypted CA archive")
	}
	mode := rest[0]
	if mode != ArchiveCryptAESGCM {
		return nil, false, errors.New("unsupported CA archive encryption")
	}
	rest = rest[1:]
	salt := rest[:CAEncSaltLen]
	rest = rest[CAEncSaltLen:]
	nonce := rest[:CAEncNonceLen]
	ciphertext := rest[CAEncNonceLen:]

	key := pbkdf2SHA256([]byte(passphrase), salt, CAEncKeyIter, CAEncKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false, errors.New("invalid CA archive passphrase or corrupted archive")
	}
	return plain, true, nil
}

func WriteCertificateArchive(w http.ResponseWriter, certDir, safeID, dataDir, exportPassphrase string) error {
	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		return err
	}
	csrPEM, err := os.ReadFile(filepath.Join(certDir, "csr.pem"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(certDir, "key.pem"))
	if err != nil {
		return err
	}
	metadataJSON, err := os.ReadFile(filepath.Join(certDir, "metadata.json"))
	if err != nil {
		return err
	}
	caCertPEM, err := os.ReadFile(filepath.Join(dataDir, "ca-cert.pem"))
	if err != nil {
		return err
	}
	intermediateCertPEM, err := os.ReadFile(filepath.Join(dataDir, "intermediate-cert.pem"))
	hasIntermediate := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	files := map[string][]byte{
		"cert.pem":      certPEM,
		"csr.pem":       csrPEM,
		"metadata.json": metadataJSON,
		"ca-cert.pem":   caCertPEM,
	}
	if exportPassphrase != "" {
		if key, parseErr := ParseUnencryptedPrivateKeyPEM(keyPEM); parseErr == nil {
			encryptedKeyPEM, encodeErr := EncodePrivateKeyPEM(key, exportPassphrase)
			if encodeErr != nil {
				return encodeErr
			}
			files["key.pem"] = encryptedKeyPEM
		} else {
			return errors.New("export passphrase can only be used with unencrypted certificate keys")
		}
	} else {
		files["key.pem"] = keyPEM
	}
	keyFiles := map[string]struct{}{
		"key.pem": {},
	}
	if hasIntermediate {
		files["intermediate-cert.pem"] = intermediateCertPEM
		issuerChain := append([]byte(nil), intermediateCertPEM...)
		issuerChain = append(issuerChain, caCertPEM...)
		files["issuer-chain.pem"] = issuerChain
	} else {
		files["issuer-chain.pem"] = append([]byte(nil), caCertPEM...)
	}
	certChain := append([]byte(nil), certPEM...)
	certChain = append(certChain, files["issuer-chain.pem"]...)
	files["chain.pem"] = certChain

	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o640,
			Size: int64(len(content)),
		}
		if _, ok := keyFiles[name]; ok {
			header.Mode = 0o600
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(content); err != nil {
			return err
		}
	}

	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+safeID+".tar.gz\"")
	_, err = w.Write(archive.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// WriteCertificateP12 exports a certificate as a PKCS#12 (.p12) file so it
// can be imported directly into browsers and OS keychains for mutual TLS.
func WriteCertificateP12(w http.ResponseWriter, certDir, safeID, dataDir, exportPassphrase string) error {
	keyPEM, err := os.ReadFile(filepath.Join(certDir, "key.pem"))
	if err != nil {
		return err
	}
	privateKey, err := ParseUnencryptedPrivateKeyPEM(keyPEM)
	if err != nil {
		return errors.New("certificate private key is encrypted: remove or disable the key passphrase before exporting a .p12")
	}

	certPEM, err := os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		return err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("certificate PEM is invalid")
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	var caCerts []*x509.Certificate
	caPEM, err := os.ReadFile(filepath.Join(dataDir, "ca-cert.pem"))
	if err == nil {
		if block, _ := pem.Decode(caPEM); block != nil {
			if caCert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				caCerts = append(caCerts, caCert)
			}
		}
	}
	if intPEM, err := os.ReadFile(filepath.Join(dataDir, "intermediate-cert.pem")); err == nil {
		if block, _ := pem.Decode(intPEM); block != nil {
			if intCert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				caCerts = append([]*x509.Certificate{intCert}, caCerts...)
			}
		}
	}

	p12Password := exportPassphrase
	if p12Password == "" {
		p12Password = pkcs12.DefaultPassword
	}
	pfxData, err := pkcs12.Modern2026.Encode(privateKey, leaf, caCerts, p12Password)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+safeID+".p12\"")
	_, err = w.Write(pfxData)
	return err
}
