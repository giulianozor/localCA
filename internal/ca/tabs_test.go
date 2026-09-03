package ca

import (
	"testing"
)

func TestCertTableArgsFiltersByType(t *testing.T) {
	a := &App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	mustCreate := func(cn, typ string) {
		if err := a.CreateServerCert(cn, nil, 1, "", "", false, typ); err != nil {
			t.Fatalf("CreateServerCert(%s) error = %v", typ, err)
		}
	}
	mustCreate("srv.local", "server")
	mustCreate("alice", "client")
	mustCreate("device-1", "dot1x")
	mustCreate("signer", "codeSigning")

	certs, err := a.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	root := PageData{
		Certificates: certs,
		T:            a.Translations["en"],
	}

	for _, tc := range []struct {
		typ  string
		want int
	}{
		{"server", 1},
		{"client", 1},
		{"dot1x", 1},
		{"codeSigning", 1},
	} {
		ctx := CertTableArgs(root, tc.typ, "title")
		if len(ctx.Certificates) != tc.want {
			t.Fatalf("CertTableArgs(%s) had %d certs, want %d", tc.typ, len(ctx.Certificates), tc.want)
		}
		if ctx.CertType != tc.typ {
			t.Fatalf("CertTableArgs CertType = %q, want %q", ctx.CertType, tc.typ)
		}
	}
}
