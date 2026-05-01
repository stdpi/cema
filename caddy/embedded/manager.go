// Package embedded provides an in-process CEMA certificate manager for Caddy.
package embedded

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/stdpi/cema/caddy/cemaapp"
	"github.com/stdpi/cema/internal/issuer"
	"github.com/stdpi/cema/internal/store"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Manager{})
}

// Manager issues and serves certificates inside the Caddy process.
type Manager struct {
	// StoragePrefix is the key prefix used inside Caddy storage.
	StoragePrefix string `json:"storage_prefix,omitempty"`

	// MinCacheValidity controls when an existing cert should be refreshed.
	MinCacheValidity caddy.Duration `json:"min_cache_validity,omitempty"`

	logger *zap.Logger
	app    *cemaapp.App
	store  store.Store
	issuer issuer.Issuer
	state  *managerState
}

type managerState struct {
	locks sync.Map
}

// CaddyModule returns the Caddy module information.
func (Manager) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.cema",
		New: func() caddy.Module { return new(Manager) },
	}
}

// Provision wires the manager to Caddy storage.
func (m *Manager) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	if m.MinCacheValidity == 0 {
		m.MinCacheValidity = caddy.Duration(24 * time.Hour)
	}
	if app, err := ctx.App("cema"); err == nil {
		if cema, ok := app.(*cemaapp.App); ok && (cema.Role == cemaapp.RoleManager || cema.Manager != "") {
			m.app = cema
			return nil
		}
	}
	cmStore, err := store.NewCertMagicStore(ctx.Storage(), m.StoragePrefix)
	if err != nil {
		return fmt.Errorf("create caddy storage store: %w", err)
	}
	m.store = cmStore
	m.issuer = issuer.NewSelfSignedIssuer()
	m.state = &managerState{}
	return nil
}

// GetCertificate returns a certificate using in-process issue/cache logic.
func (m *Manager) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSpace(strings.ToLower(hello.ServerName))
	if name == "" {
		return nil, nil
	}

	lock := m.domainLock(name)
	lock.Lock()
	defer lock.Unlock()

	if m.app != nil {
		record, err := m.app.GetCertificateRecord(ctx, name, time.Duration(m.MinCacheValidity))
		if err != nil {
			return nil, err
		}
		return certFromBundle(record.BundlePEM)
	}

	record, err := m.store.Get(ctx, name)
	if err == nil && time.Until(record.NotAfter) > time.Duration(m.MinCacheValidity) {
		return certFromBundle(record.BundlePEM)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	record, err = m.issuer.Issue(ctx, issuer.CertificateRequest{Domain: name})
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}
	if err := m.store.Put(ctx, record); err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}
	m.logger.Info("embedded cema certificate ready", zap.String("server_name", name), zap.Time("expires", record.NotAfter))
	return certFromBundle(record.BundlePEM)
}

// UnmarshalCaddyfile parses:
//
//	get_certificate cema {
//		storage_prefix <prefix>
//		min_cache_validity <duration>
//	}
func (m *Manager) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "storage_prefix":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.StoragePrefix = d.Val()
		case "min_cache_validity":
			if !d.NextArg() {
				return d.ArgErr()
			}
			duration, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return err
			}
			m.MinCacheValidity = caddy.Duration(duration)
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

func (m *Manager) domainLock(name string) *sync.Mutex {
	if m.state == nil {
		m.state = &managerState{}
	}
	value, _ := m.state.locks.LoadOrStore(name, new(sync.Mutex))
	lock, ok := value.(*sync.Mutex)
	if !ok {
		return new(sync.Mutex)
	}
	return lock
}

func certFromBundle(bundle string) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(bundle), []byte(bundle))
	if err != nil {
		return nil, fmt.Errorf("parse certificate bundle: %w", err)
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

var (
	_ certmagic.Manager     = (*Manager)(nil)
	_ caddy.Provisioner     = (*Manager)(nil)
	_ caddyfile.Unmarshaler = (*Manager)(nil)
)
