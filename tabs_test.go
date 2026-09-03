package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertTableArgsFiltersByType(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	mustCreate := func(cn, typ string) {
		if err := a.createServerCert(cn, nil, 1, "", "", false, typ); err != nil {
			t.Fatalf("createServerCert(%s) error = %v", typ, err)
		}
	}
	mustCreate("srv.local", "server")
	mustCreate("alice", "client")
	mustCreate("device-1", "dot1x")
	mustCreate("signer", "codeSigning")

	certs, err := a.listCerts()
	if err != nil {
		t.Fatalf("listCerts() error = %v", err)
	}
	root := pageData{
		Certificates: certs,
		T:            a.translations["en"],
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
		ctx := certTableArgs(root, tc.typ, "title")
		if len(ctx.Certificates) != tc.want {
			t.Fatalf("certTableArgs(%s) had %d certs, want %d", tc.typ, len(ctx.Certificates), tc.want)
		}
		if ctx.CertType != tc.typ {
			t.Fatalf("certTableArgs CertType = %q, want %q", ctx.CertType, tc.typ)
		}
	}
}

func TestHandleCertTableFiltersByType(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("srv.local", nil, 1, "", "", false, "server"); err != nil {
		t.Fatalf("server cert error = %v", err)
	}
	if err := a.createServerCert("alice", nil, 1, "", "", false, "client"); err != nil {
		t.Fatalf("client cert error = %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/certs/table?type=client", nil)
	a.handleCertTable(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleCertTable status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alice") {
		t.Fatalf("table body missing client cert: %q", body)
	}
	if strings.Contains(body, "srv.local") {
		t.Fatalf("table body should not contain server cert in client view: %q", body)
	}

	// Unknown type is rejected.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/certs/table?type=bogus", nil)
	a.handleCertTable(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown type, got %d", rr2.Code)
	}
}

func TestIndexRendersTabsAndPerTypeForms(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	tr, err := loadTranslations()
	if err != nil {
		t.Fatalf("loadTranslations() error = %v", err)
	}
	a.translations = tr
	if err := a.createCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("createCA() error = %v", err)
	}
	if err := a.createServerCert("myserver.example.com", []string{"myserver.example.com"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("server cert error = %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	a.handleIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleIndex status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	for _, marker := range []string{
		`class="tabs js-tabs"`,
		`data-tab="ca"`,
		`data-tab="server"`,
		`data-tab="client"`,
		`data-tab="dot1x"`,
		`data-tab="code"`,
		`id="tab-ca"`,
		`id="tab-server"`,
		`id="tab-client"`,
		`id="tab-dot1x"`,
		`id="tab-code"`,
		`name="cert_type" value="server"`,
		`name="cert_type" value="client"`,
		`name="cert_type" value="dot1x"`,
		`name="cert_type" value="codeSigning"`,
		`data-type="server"`,
		`data-type="client"`,
		`data-type="dot1x"`,
		`data-type="codeSigning"`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("index page missing marker %q", marker)
		}
	}
}

func TestIndexRendersNoTabsBeforeCA(t *testing.T) {
	a := &app{dataDir: t.TempDir(), defaultLang: "en"}
	tr, err := loadTranslations()
	if err != nil {
		t.Fatalf("loadTranslations() error = %v", err)
	}
	a.translations = tr
	if err := os.MkdirAll(filepath.Join(a.dataDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	a.handleIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleIndex status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `class="tabs js-tabs"`) {
		t.Fatal("index should not render tabs before a CA exists")
	}
}
