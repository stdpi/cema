// Package handlers contains CEMA HTTP handlers.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stdpi/cema/caddy/cemaapp"
	"github.com/stdpi/cema/internal/issuer"
	"github.com/stdpi/cema/internal/store"
)

func init() {
	caddy.RegisterModule(API{})
	httpcaddyfile.RegisterHandlerDirective("cema_api", parseAPI)
}

// API serves manager HTTP API routes through Caddy.
type API struct {
	app *cemaapp.App
}

// CaddyModule returns module info.
func (API) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cema_api",
		New: func() caddy.Module { return new(API) },
	}
}

// Provision gets the CEMA app.
func (h *API) Provision(ctx caddy.Context) error {
	app, err := ctx.App("cema")
	if err != nil {
		return err
	}
	cema, ok := app.(*cemaapp.App)
	if !ok {
		return errors.New("unexpected cema app type")
	}
	h.app = cema
	return nil
}

// ServeHTTP serves CEMA API routes.
func (h API) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !h.app.Authenticate(r) {
		writeJSON(w, http.StatusUnauthorized, cemaapp.CertificateResponse{Status: "error", Error: "unauthorized"})
		return nil
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/certificates/request":
		h.handleRequestCertificate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/certificates/"):
		h.handleGetCertificate(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/certificates/"):
		h.handleDeleteCertificate(w, r)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/challenges/http-01/"):
		h.handlePutHTTPChallenge(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		return next.ServeHTTP(w, r)
	}
	return nil
}

func (h API) handleRequestCertificate(w http.ResponseWriter, r *http.Request) {
	var request issuer.CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, cemaapp.CertificateResponse{Status: "error", Error: err.Error()})
		return
	}
	record, err := h.app.GetCertificateRecord(r.Context(), request.Domain, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, cemaapp.CertificateResponse{Status: "error", Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, recordResponse(record, false))
}

func (h API) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/certificates/")
	record, err := h.app.GetStoredCertificateRecord(r.Context(), domain)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, cemaapp.CertificateResponse{Status: "error", Error: err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, cemaapp.CertificateResponse{Status: "error", Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, recordResponse(record, true))
}

func (h API) handleDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/certificates/")
	err := h.app.DeleteCertificateRecord(r.Context(), domain)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, cemaapp.CertificateResponse{Status: "error", Error: err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, cemaapp.CertificateResponse{Status: "error", Error: err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h API) handlePutHTTPChallenge(w http.ResponseWriter, r *http.Request) {
	var task cemaapp.ChallengeTask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	task.Type = "http-01"
	if err := h.app.PutChallenge(task); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func parseAPI(_ httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return new(API), nil
}

func recordResponse(record *store.CertificateRecord, cached bool) cemaapp.CertificateResponse {
	return cemaapp.CertificateResponse{
		Status:      "ready",
		Domain:      record.Domain,
		Certificate: record.BundlePEM,
		Expires:     record.NotAfter,
		Cached:      cached,
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var (
	_ caddy.Provisioner           = (*API)(nil)
	_ caddyhttp.MiddlewareHandler = (*API)(nil)
)
