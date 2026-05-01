package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stdpi/cema/internal/issuer"
	"github.com/stdpi/cema/internal/store"
)

func TestServerRequestAndGetCertificate(t *testing.T) {
	t.Parallel()

	fs, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	server := NewServer(Config{
		Store:  fs,
		Issuer: issuer.NewSelfSignedIssuer(),
		APIKey: "secret",
	})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	body := bytes.NewBufferString(`{"domain":"example.com","sans":["www.example.com"]}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/certificates/request", body)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", resp.StatusCode)
	}

	var postResp certificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&postResp); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if postResp.Certificate == "" {
		t.Fatal("certificate is empty")
	}

	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/certificates/example.com", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	req.Header.Set("X-API-Key", "secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
}

func TestServerRequiresAPIKey(t *testing.T) {
	t.Parallel()

	fs, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	server := NewServer(Config{
		Store:  fs,
		Issuer: issuer.NewSelfSignedIssuer(),
		APIKey: "secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
