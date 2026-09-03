package ca

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

func TestServerCertificateKeyUsage(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("srv.local", []string{"srv.local"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("CreateServerCert(server) error = %v", err)
	}
	certs, _ := a.ListCerts()
	meta := certs[0]
	cert := parseCertificatePEM(t, filepath.Join(a.DataDir, "certs", meta.ID, "cert.pem"))
	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("server certificate missing ExtKeyUsageServerAuth")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("server certificate missing KeyUsageKeyEncipherment")
	}
}

func containsExtKeyUsage(usages []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, u := range usages {
		if u == want {
			return true
		}
	}
	return false
}
