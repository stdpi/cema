// Package cemaapp implements the CEMA Caddy app.
package cemaapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stdpi/cema/internal/issuer"
	"github.com/stdpi/cema/internal/store"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

const (
	// RoleManager makes this node issue and serve cert records.
	RoleManager = "manager"
	// RoleReplica makes this node fetch cert records from a manager.
	RoleReplica = "replica"
)

// App is the CEMA Caddy app.
type App struct {
	// Role is "manager" or "replica".
	Role string `json:"role,omitempty"`

	// Token authenticates manager/replica API calls.
	Token string `json:"token,omitempty"`

	// Manager is the base URL of the tier-0 manager for replicas.
	Manager string `json:"manager,omitempty"`

	// StoragePrefix is the key prefix used inside Caddy storage.
	StoragePrefix string `json:"storage_prefix,omitempty"`

	// Challenges lists enabled delegated challenge types. HTTP is implemented; TLS-ALPN/TCP are WIP.
	Challenges []string `json:"challenges,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
	store  store.Store
	issuer issuer.Issuer
	client *http.Client

	state *State
}

// State keeps runtime mutable app state.
type State struct {
	locks      sync.Map
	challenges sync.Map
}

// ChallengeTask is a delegated ACME challenge response.
type ChallengeTask struct {
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Token     string    `json:"token"`
	KeyAuth   string    `json:"key_auth"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CertificateResponse is the manager API cert response.
type CertificateResponse struct {
	Status      string    `json:"status"`
	Domain      string    `json:"domain,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Cached      bool      `json:"cached,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// CaddyModule returns the Caddy module info.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "cema",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision wires CEMA to Caddy storage.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()
	if a.Role == "" {
		a.Role = RoleReplica
	}
	if a.StoragePrefix == "" {
		a.StoragePrefix = "cema/certificates"
	}
	cmStore, err := store.NewCertMagicStore(ctx.Storage(), a.StoragePrefix)
	if err != nil {
		return fmt.Errorf("create caddy storage store: %w", err)
	}
	a.store = cmStore
	a.issuer = issuer.NewSelfSignedIssuer()
	a.client = &http.Client{Timeout: 10 * time.Second}
	a.state = &State{}
	return nil
}

// Validate checks app config.
func (a App) Validate() error {
	switch a.Role {
	case RoleManager, RoleReplica:
	default:
		return fmt.Errorf("invalid cema role %q", a.Role)
	}
	if a.Role == RoleReplica && a.Manager == "" {
		return errors.New("manager is required for cema replica")
	}
	return nil
}

// Start starts the CEMA app.
func (a *App) Start() error {
	a.logger.Info("cema app started", zap.String("role", a.Role))
	return nil
}

// Stop stops the CEMA app.
func (a *App) Stop() error {
	return nil
}

// GetCertificateRecord returns a certificate record for domain.
func (a *App) GetCertificateRecord(ctx context.Context, domain string, minValidity time.Duration) (*store.CertificateRecord, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, errors.New("domain is required")
	}

	if record, err := a.store.Get(ctx, domain); err == nil && time.Until(record.NotAfter) > minValidity {
		return record, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load local certificate: %w", err)
	}

	switch a.Role {
	case RoleManager:
		return a.issueLocal(ctx, domain, minValidity)
	case RoleReplica:
		return a.fetchFromManager(ctx, domain)
	default:
		return nil, fmt.Errorf("invalid cema role %q", a.Role)
	}
}

// GetStoredCertificateRecord returns a stored record only.
func (a *App) GetStoredCertificateRecord(ctx context.Context, domain string) (*store.CertificateRecord, error) {
	return a.store.Get(ctx, domain)
}

// DeleteCertificateRecord deletes a stored record.
func (a *App) DeleteCertificateRecord(ctx context.Context, domain string) error {
	return a.store.Delete(ctx, domain)
}

// Authenticate returns true when request token matches config, or auth is disabled.
func (a *App) Authenticate(r *http.Request) bool {
	if a.Token == "" {
		return true
	}
	header := r.Header.Get("Authorization")
	token := strings.TrimPrefix(header, "Bearer ")
	if token == "" {
		token = r.Header.Get("X-CEMA-Token")
	}
	return token == a.Token
}

// PutChallenge stores a delegated challenge task.
func (a *App) PutChallenge(task ChallengeTask) error {
	if task.Type == "" {
		task.Type = "http-01"
	}
	if task.Token == "" || task.KeyAuth == "" {
		return errors.New("challenge token and key_auth are required")
	}
	if task.ExpiresAt.IsZero() {
		task.ExpiresAt = time.Now().Add(10 * time.Minute)
	}
	a.ensureState().challenges.Store(task.Token, task)
	return nil
}

// GetHTTPChallenge returns key authorization for a token.
func (a *App) GetHTTPChallenge(token string) (string, bool) {
	state := a.ensureState()
	value, ok := state.challenges.Load(token)
	if !ok {
		return "", false
	}
	task, ok := value.(ChallengeTask)
	if !ok || task.Type != "http-01" || time.Now().After(task.ExpiresAt) {
		state.challenges.Delete(token)
		return "", false
	}
	return task.KeyAuth, true
}

func (a *App) issueLocal(ctx context.Context, domain string, minValidity time.Duration) (*store.CertificateRecord, error) {
	lock := a.domainLock(domain)
	lock.Lock()
	defer lock.Unlock()

	if record, err := a.store.Get(ctx, domain); err == nil && time.Until(record.NotAfter) > minValidity {
		return record, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load local certificate: %w", err)
	}

	record, err := a.issuer.Issue(ctx, issuer.CertificateRequest{Domain: domain})
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}
	if err := a.store.Put(ctx, record); err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}
	a.logger.Info("cema manager certificate ready", zap.String("domain", domain), zap.Time("expires", record.NotAfter))
	return record, nil
}

func (a *App) fetchFromManager(ctx context.Context, domain string) (*store.CertificateRecord, error) {
	response, err := a.managerRequest(ctx, http.MethodGet, "/certificates/"+url.PathEscape(domain), nil)
	if err == nil && response.Certificate != "" {
		return a.storeManagerResponse(ctx, response)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	body, err := json.Marshal(map[string]string{"domain": domain})
	if err != nil {
		return nil, fmt.Errorf("encode certificate request: %w", err)
	}
	response, err = a.managerRequest(ctx, http.MethodPost, "/certificates/request", body)
	if err != nil {
		return nil, err
	}
	return a.storeManagerResponse(ctx, response)
}

func (a *App) storeManagerResponse(ctx context.Context, response CertificateResponse) (*store.CertificateRecord, error) {
	if response.Certificate == "" {
		return nil, errors.New("manager response missing certificate")
	}
	record := &store.CertificateRecord{
		Domain:    response.Domain,
		BundlePEM: response.Certificate,
		CertPEM:   response.Certificate,
		NotAfter:  response.Expires,
		UpdatedAt: time.Now(),
	}
	if record.Domain == "" {
		return nil, errors.New("manager response missing domain")
	}
	if err := a.store.Put(ctx, record); err != nil {
		return nil, fmt.Errorf("store manager certificate: %w", err)
	}
	return record, nil
}

func (a *App) managerRequest(ctx context.Context, method, apiPath string, body []byte) (CertificateResponse, error) {
	endpoint := strings.TrimRight(a.Manager, "/") + apiPath
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return CertificateResponse{}, fmt.Errorf("create manager request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return CertificateResponse{}, fmt.Errorf("call manager: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return CertificateResponse{}, store.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return CertificateResponse{}, fmt.Errorf("manager returned HTTP %d", resp.StatusCode)
	}

	var response CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return CertificateResponse{}, fmt.Errorf("decode manager response: %w", err)
	}
	return response, nil
}

func (a *App) domainLock(domain string) *sync.Mutex {
	value, _ := a.ensureState().locks.LoadOrStore(domain, new(sync.Mutex))
	lock, ok := value.(*sync.Mutex)
	if !ok {
		return new(sync.Mutex)
	}
	return lock
}

func (a *App) ensureState() *State {
	if a.state == nil {
		a.state = &State{}
	}
	return a.state
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Validator   = (*App)(nil)
)
