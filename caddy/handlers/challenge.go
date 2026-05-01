package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stdpi/cema/caddy/cemaapp"
)

func init() {
	caddy.RegisterModule(Challenge{})
	httpcaddyfile.RegisterHandlerDirective("cema_challenge", parseChallenge)
}

// Challenge serves delegated HTTP-01 challenge responses.
type Challenge struct {
	app *cemaapp.App
}

// CaddyModule returns module info.
func (Challenge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cema_challenge",
		New: func() caddy.Module { return new(Challenge) },
	}
}

// Provision gets the CEMA app.
func (h *Challenge) Provision(ctx caddy.Context) error {
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

// ServeHTTP serves challenge requests or delegates to next.
func (h Challenge) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	const prefix = "/.well-known/acme-challenge/"
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, prefix) {
		return next.ServeHTTP(w, r)
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	keyAuth, ok := h.app.GetHTTPChallenge(token)
	if !ok {
		return next.ServeHTTP(w, r)
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(keyAuth))
	return nil
}

func parseChallenge(_ httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return new(Challenge), nil
}

var (
	_ caddy.Provisioner           = (*Challenge)(nil)
	_ caddyhttp.MiddlewareHandler = (*Challenge)(nil)
)
