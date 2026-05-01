package cemaapp

import (
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("cema", parseGlobalOption)
}

func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next()

	app := new(App)
	if d.NextArg() {
		app.Role = d.Val()
	}
	if d.NextArg() {
		return nil, d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "role":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Role = d.Val()
		case "token":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Token = d.Val()
		case "manager":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Manager = d.Val()
		case "storage_prefix":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.StoragePrefix = d.Val()
		case "challenges":
			for d.NextBlock(1) {
				app.Challenges = append(app.Challenges, d.Val())
				if d.NextArg() {
					return nil, d.ArgErr()
				}
			}
		default:
			return nil, d.Errf("unrecognized cema option %q", d.Val())
		}
		if d.NextArg() {
			return nil, d.ArgErr()
		}
	}

	return httpcaddyfile.App{
		Name:  "cema",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
