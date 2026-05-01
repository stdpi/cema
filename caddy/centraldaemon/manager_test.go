package centraldaemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stdpi/cema/internal/issuer"
	"go.uber.org/zap"
)

func TestManagerRequestsAndCachesCertificate(t *testing.T) {
	t.Parallel()

	issued, err := issuer.NewSelfSignedIssuer().Issue(context.Background(), issuer.CertificateRequest{Domain: "example.com"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/certificates/request" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(certificateResponse{
			Status:      "ready",
			Domain:      issued.Domain,
			Certificate: issued.BundlePEM,
			Expires:     issued.NotAfter,
		})
	}))
	defer ts.Close()

	manager := testManager(t, ts.URL)
	cert, err := manager.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("certificate or leaf is nil")
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}

	cert, err = manager.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate() cached error = %v", err)
	}
	if cert == nil {
		t.Fatal("cached certificate is nil")
	}
	if requests != 2 {
		t.Fatalf("requests after cache = %d, want 2", requests)
	}
}

func TestManagerFallsBackToDiskCache(t *testing.T) {
	t.Parallel()

	issued, err := issuer.NewSelfSignedIssuer().Issue(context.Background(), issuer.CertificateRequest{Domain: "example.com"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	manager := testManager(t, "http://127.0.0.1:1")
	cert, err := tls.X509KeyPair([]byte(issued.BundlePEM), []byte(issued.BundlePEM))
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	if err := manager.storeDisk("example.com", &cert); err != nil {
		t.Fatalf("storeDisk() error = %v", err)
	}

	got, err := manager.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	if got == nil {
		t.Fatal("fallback certificate is nil")
	}
}

func testManager(t *testing.T, daemonURL string) *CentralDaemonManager {
	t.Helper()
	return &CentralDaemonManager{
		DaemonURL:        daemonURL,
		Timeout:          caddy.Duration(time.Second),
		CacheDir:         t.TempDir(),
		MinCacheValidity: caddy.Duration(24 * time.Hour),
		logger:           zap.NewNop(),
		client:           &http.Client{Timeout: time.Second},
		state:            &managerState{},
	}
}
