// Package daemon exposes the CEMA certificate REST API.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stdpi/cema/internal/issuer"
	"github.com/stdpi/cema/internal/store"
)

const renewBefore = 30 * 24 * time.Hour

// Config configures a daemon server.
type Config struct {
	Store  store.Store
	Issuer issuer.Issuer
	APIKey string
	Logger *slog.Logger
}

// Server handles certificate API requests.
type Server struct {
	store  store.Store
	issuer issuer.Issuer
	apiKey string
	logger *slog.Logger

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewServer creates a certificate daemon server.
func NewServer(config Config) *Server {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:  config.Store,
		issuer: config.Issuer,
		apiKey: config.APIKey,
		logger: logger,
		locks:  make(map[string]*sync.Mutex),
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /certificates/request", s.handleRequestCertificate)
	mux.HandleFunc("GET /certificates/{domain}", s.handleGetCertificate)
	mux.HandleFunc("DELETE /certificates/{domain}", s.handleDeleteCertificate)
	return s.auth(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRequestCertificate(w http.ResponseWriter, r *http.Request) {
	var request issuer.CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	request.Domain = strings.TrimSpace(strings.ToLower(request.Domain))
	if request.Domain == "" {
		writeError(w, http.StatusBadRequest, errors.New("domain is required"))
		return
	}

	record, cached, err := s.getOrIssue(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, certificateResponse{
		Status:      "ready",
		Domain:      record.Domain,
		Certificate: record.BundlePEM,
		Expires:     record.NotAfter,
		Cached:      cached,
	})
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(strings.ToLower(r.PathValue("domain")))
	record, err := s.store.Get(r.Context(), domain)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, certificateResponse{
		Status:      "ready",
		Domain:      record.Domain,
		Certificate: record.BundlePEM,
		Expires:     record.NotAfter,
		Cached:      true,
	})
}

func (s *Server) handleDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(strings.ToLower(r.PathValue("domain")))
	err := s.store.Delete(r.Context(), domain)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getOrIssue(ctx context.Context, request issuer.CertificateRequest) (*store.CertificateRecord, bool, error) {
	lock := s.domainLock(request.Domain)
	lock.Lock()
	defer lock.Unlock()

	if !request.Force {
		record, err := s.store.Get(ctx, request.Domain)
		if err == nil && time.Until(record.NotAfter) > renewBefore {
			return record, true, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, false, fmt.Errorf("read cached cert: %w", err)
		}
	}

	record, err := s.issuer.Issue(ctx, request)
	if err != nil {
		return nil, false, fmt.Errorf("issue certificate: %w", err)
	}
	if err := s.store.Put(ctx, record); err != nil {
		return nil, false, fmt.Errorf("store certificate: %w", err)
	}
	s.logger.Info("certificate ready", "domain", record.Domain, "expires", record.NotAfter)
	return record, false, nil
}

func (s *Server) domainLock(domain string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, ok := s.locks[domain]
	if !ok {
		lock = new(sync.Mutex)
		s.locks[domain] = lock
	}
	return lock
}

func (s *Server) auth(next http.Handler) http.Handler {
	if s.apiKey == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if token == "" {
			token = r.Header.Get("X-API-Key")
		}
		if token != s.apiKey {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

type certificateResponse struct {
	Status      string    `json:"status"`
	Domain      string    `json:"domain,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Cached      bool      `json:"cached,omitempty"`
	Error       string    `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, certificateResponse{
		Status: "error",
		Error:  err.Error(),
	})
}
