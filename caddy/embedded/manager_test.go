package embedded

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/stdpi/cema/internal/issuer"
	"github.com/stdpi/cema/internal/store"
	"go.uber.org/zap"
)

func TestManagerIssuesAndStoresInCaddyStorage(t *testing.T) {
	t.Parallel()

	cmStore, err := store.NewCertMagicStore(&certmagic.FileStorage{Path: t.TempDir()}, "")
	if err != nil {
		t.Fatalf("NewCertMagicStore() error = %v", err)
	}
	manager := &Manager{
		MinCacheValidity: caddy.Duration(24 * time.Hour),
		logger:           zap.NewNop(),
		store:            cmStore,
		issuer:           issuer.NewSelfSignedIssuer(),
		state:            &managerState{},
	}

	cert, err := manager.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("certificate or leaf is nil")
	}

	record, err := cmStore.Get(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if record.BundlePEM == "" {
		t.Fatal("stored bundle empty")
	}
}
