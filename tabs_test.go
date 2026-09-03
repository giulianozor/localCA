package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giulianozor/localCA/internal/ca"
)

func TestHandleCertTableFiltersByType(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("srv.local", nil, 1, "", "", false, "server"); err != nil {
		t.Fatalf("server cert error = %v", err)
	}
	if err := a.CreateServerCert("alice", nil, 1, "", "", false, "client"); err != nil {
		t.Fatalf("client cert error = %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/certs/table?type=client", nil)
	handleCertTable(a, rr, req)
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
	handleCertTable(a, rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown type, got %d", rr2.Code)
	}
}

func TestIndexRendersTabsAndPerTypeForms(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	tr, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	a.Translations = tr
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("myserver.example.com", []string{"myserver.example.com"}, 1, "", "", false, "server"); err != nil {
		t.Fatalf("server cert error = %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handleIndex(a, rr, req)
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
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	tr, err := ca.LoadTranslations()
	if err != nil {
		t.Fatalf("LoadTranslations() error = %v", err)
	}
	a.Translations = tr
	if err := os.MkdirAll(filepath.Join(a.DataDir, "certs"), 0o750); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handleIndex(a, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleIndex status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `class="tabs js-tabs"`) {
		t.Fatal("index should not render tabs before a CA exists")
	}
}
