package ca

import (
	"testing"
)

func TestCreateServerCertRecordsSigner(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("ca-signed.local", []string{"ca-signed.local"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("CreateServerCert(ca) error = %v", err)
	}
	if err := a.CreateIntermediateCA("Test Intermediate", "localCA", "IT", "", ""); err != nil {
		t.Fatalf("CreateIntermediateCA() error = %v", err)
	}
	if err := a.CreateServerCert("intermediate-signed.local", []string{"intermediate-signed.local"}, 1, "", "", true, "server"); err != nil {
		t.Fatalf("CreateServerCert(intermediate) error = %v", err)
	}

	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("ListCerts() len = %d, want 2", len(certs))
	}
	for _, c := range certs {
		want := "ca"
		if c.CommonName == "intermediate-signed.local" {
			want = "intermediate"
		}
		if c.Signer != want {
			t.Fatalf("cert %s signer = %q, want %q", c.CommonName, c.Signer, want)
		}
	}
}

func TestSignerNameFallback(t *testing.T) {
	tests := []struct {
		name            string
		signer          string
		hasIntermediate bool
		want            string
	}{
		{name: "explicit ca", signer: "ca", hasIntermediate: true, want: "ca"},
		{name: "explicit intermediate", signer: "intermediate", hasIntermediate: true, want: "intermediate"},
		{name: "legacy with intermediate", signer: "", hasIntermediate: true, want: "intermediate"},
		{name: "legacy root only", signer: "", hasIntermediate: false, want: "ca"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := CertMetadata{Signer: tt.signer}
			if got := m.SignerName(tt.hasIntermediate); got != tt.want {
				t.Fatalf("SignerName() = %q, want %q", got, tt.want)
			}
		})
	}
}
