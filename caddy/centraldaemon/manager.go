// Package centraldaemon provides a Caddy certificate manager for CEMA.
package centraldaemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CentralDaemonManager{})
}

// CentralDaemonManager gets certificates from a CEMA daemon and caches them on disk.
type CentralDaemonManager struct {
	// DaemonURL is the base URL of the CEMA daemon.
	DaemonURL string `json:"daemon_url,omitempty"`

	// Timeout bounds daemon HTTP requests.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// CacheDir stores PEM bundles so Caddy can boot and serve when daemon is down.
	CacheDir string `json:"cache_dir,omitempty"`

	// APIKey is sent as a bearer token when non-empty.
	APIKey string `json:"api_key,omitempty"`

	// MinCacheValidity is how long a cached cert must remain valid before daemon refresh is attempted.
	MinCacheValidity caddy.Duration `json:"min_cache_validity,omitempty"`

	ctx    context.Context
	logger *zap.Logger
	client *http.Client
	state  *managerState
}

type managerState struct {
	certs sync.Map
}

// CaddyModule returns the Caddy module information.
func (CentralDaemonManager) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.central_daemon",
		New: func() caddy.Module { return new(CentralDaemonManager) },
	}
}

// Provision prepares the manager runtime.
func (cdm *CentralDaemonManager) Provision(ctx caddy.Context) error {
	cdm.ctx = ctx
	cdm.logger = ctx.Logger()
	if cdm.Timeout == 0 {
		cdm.Timeout = caddy.Duration(5 * time.Second)
	}
	if cdm.MinCacheValidity == 0 {
		cdm.MinCacheValidity = caddy.Duration(24 * time.Hour)
	}
	if cdm.CacheDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("resolve cache dir: %w", err)
		}
		cdm.CacheDir = filepath.Join(cacheDir, "cema-caddy")
	}
	if err := os.MkdirAll(cdm.CacheDir, 0o700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	cdm.client = &http.Client{Timeout: time.Duration(cdm.Timeout)}
	cdm.state = &managerState{}
	return nil
}

// Validate validates manager config.
func (cdm CentralDaemonManager) Validate() error {
	if cdm.DaemonURL == "" {
		return errors.New("daemon_url is required")
	}
	parsed, err := url.Parse(cdm.DaemonURL)
	if err != nil {
		return fmt.Errorf("parse daemon_url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("daemon_url must use http or https")
	}
	if parsed.Host == "" {
		return errors.New("daemon_url host is required")
	}
	return nil
}

// GetCertificate returns a certificate for the TLS handshake.
func (cdm *CentralDaemonManager) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSpace(strings.ToLower(hello.ServerName))
	if name == "" {
		return nil, nil
	}

	if cert := cdm.memoryCached(name); cert != nil && certValidFor(cert, time.Duration(cdm.MinCacheValidity)) {
		return cert, nil
	}

	diskCert, diskErr := cdm.loadDisk(name)
	if diskErr == nil && certValidFor(diskCert, time.Duration(cdm.MinCacheValidity)) {
		cdm.remember(name, diskCert)
		return diskCert, nil
	}

	daemonCert, err := cdm.fetch(ctx, name)
	if err == nil {
		cdm.remember(name, daemonCert)
		if cacheErr := cdm.storeDisk(name, daemonCert); cacheErr != nil {
			cdm.logger.Warn("cache certificate", zap.String("server_name", name), zap.Error(cacheErr))
		}
		return daemonCert, nil
	}

	if diskErr == nil && certValidFor(diskCert, 0) {
		cdm.logger.Warn("serving cached certificate after daemon failure", zap.String("server_name", name), zap.Error(err))
		cdm.remember(name, diskCert)
		return diskCert, nil
	}

	return nil, err
}

// UnmarshalCaddyfile parses:
//
//	get_certificate central_daemon <daemon_url> {
//		cache_dir <path>
//		api_key <token>
//		timeout <duration>
//		min_cache_validity <duration>
//	}
func (cdm *CentralDaemonManager) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if !d.NextArg() {
		return d.ArgErr()
	}
	cdm.DaemonURL = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "cache_dir":
			if !d.NextArg() {
				return d.ArgErr()
			}
			cdm.CacheDir = d.Val()
		case "api_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			cdm.APIKey = d.Val()
		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			duration, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return err
			}
			cdm.Timeout = caddy.Duration(duration)
		case "min_cache_validity":
			if !d.NextArg() {
				return d.ArgErr()
			}
			duration, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return err
			}
			cdm.MinCacheValidity = caddy.Duration(duration)
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

func (cdm *CentralDaemonManager) memoryCached(name string) *tls.Certificate {
	if cdm.state == nil {
		return nil
	}
	cert, ok := cdm.state.certs.Load(name)
	if !ok {
		return nil
	}
	typed, ok := cert.(*tls.Certificate)
	if !ok {
		return nil
	}
	return typed
}

func (cdm *CentralDaemonManager) remember(name string, cert *tls.Certificate) {
	if cdm.state == nil {
		cdm.state = &managerState{}
	}
	cdm.state.certs.Store(name, cert)
}

func (cdm *CentralDaemonManager) fetch(ctx context.Context, name string) (*tls.Certificate, error) {
	cert, err := cdm.fetchExisting(ctx, name)
	if err == nil && cert != nil {
		return cert, nil
	}
	if err != nil {
		return nil, err
	}
	return cdm.requestCertificate(ctx, name)
}

func (cdm *CentralDaemonManager) fetchExisting(ctx context.Context, name string) (*tls.Certificate, error) {
	endpoint := strings.TrimRight(cdm.DaemonURL, "/") + "/certificates/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create daemon request: %w", err)
	}
	if cdm.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cdm.APIKey)
	}

	resp, err := cdm.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch daemon certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}

	var response certificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode daemon response: %w", err)
	}
	if response.Certificate == "" {
		return nil, errors.New("daemon response missing certificate")
	}

	cert, err := tls.X509KeyPair([]byte(response.Certificate), []byte(response.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parse daemon certificate: %w", err)
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

func (cdm *CentralDaemonManager) requestCertificate(ctx context.Context, name string) (*tls.Certificate, error) {
	endpoint := strings.TrimRight(cdm.DaemonURL, "/") + "/certificates/request"
	payload := []byte(fmt.Sprintf(`{"domain":%q}`, name))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create daemon request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cdm.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cdm.APIKey)
	}

	resp, err := cdm.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request daemon certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}

	var response certificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode daemon response: %w", err)
	}
	if response.Certificate == "" {
		return nil, errors.New("daemon response missing certificate")
	}

	cert, err := tls.X509KeyPair([]byte(response.Certificate), []byte(response.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parse daemon certificate: %w", err)
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

func (cdm *CentralDaemonManager) loadDisk(name string) (*tls.Certificate, error) {
	data, err := os.ReadFile(cdm.cachePath(name))
	if err != nil {
		return nil, fmt.Errorf("read cached certificate: %w", err)
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("parse cached certificate: %w", err)
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse cached leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

func (cdm *CentralDaemonManager) storeDisk(name string, cert *tls.Certificate) error {
	pemBundle, err := pemBundle(cert)
	if err != nil {
		return err
	}
	path := cdm.cachePath(name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pemBundle, 0o600); err != nil {
		return fmt.Errorf("write cache temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit cache file: %w", err)
	}
	return nil
}

func (cdm *CentralDaemonManager) cachePath(name string) string {
	safe := strings.NewReplacer("*", "_wildcard_", "/", "_", "\\", "_", ":", "_").Replace(strings.ToLower(name))
	return filepath.Join(cdm.CacheDir, safe+".pem")
}

type certificateResponse struct {
	Status      string    `json:"status"`
	Domain      string    `json:"domain,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Cached      bool      `json:"cached,omitempty"`
	Error       string    `json:"error,omitempty"`
}

var (
	_ certmagic.Manager     = (*CentralDaemonManager)(nil)
	_ caddy.Provisioner     = (*CentralDaemonManager)(nil)
	_ caddy.Validator       = (*CentralDaemonManager)(nil)
	_ caddyfile.Unmarshaler = (*CentralDaemonManager)(nil)
)
