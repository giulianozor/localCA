package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/giulianozor/localCA/internal/ca"
)

func TestExportDot1xCertP12(t *testing.T) {
	a := &ca.App{DataDir: t.TempDir(), DefaultLang: "en"}
	if err := a.CreateCA("Test Root", "localCA", "IT", ""); err != nil {
		t.Fatalf("CreateCA() error = %v", err)
	}
	if err := a.CreateServerCert("device-07ab", nil, 1, "", "", false, "dot1x"); err != nil {
		t.Fatalf("CreateServerCert(dot1x) error = %v", err)
	}
	certs, _ := a.ListCerts()
	id := certs[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download?kind=client-p12&id="+id+"&export_passphrase=pass", nil)
	handleDownload(a, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("dot1x p12 download status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "pkcs12") {
		t.Fatalf("Content-Type = %q, want pkcs12", rr.Header().Get("Content-Type"))
	}
}
