# Repository Guidelines

## Project Structure & Module Organization

CEMA is a Go module for Caddy certificate coordination. Root package `cema.go` registers Caddy modules through blank imports. Caddy integration lives under `caddy/`: `cemaapp` contains the `cema` app and Caddyfile global option parser, `embedded` contains `tls.get_certificate.cema`, `handlers` contains `cema_api` and `cema_challenge`, and `centraldaemon` keeps the older external-daemon getter. Core non-Caddy logic is under `internal/`: `store` provides file and CertMagic-backed storage, `issuer` contains the MVP self-signed issuer, and `daemon` contains the standalone REST server. CLI entrypoint is `cmd/cema-daemon`.

## Build, Test, and Development Commands

- `go test ./...`: run all unit tests.
- `go test -race ./...`: run tests with race detection before concurrency-sensitive changes.
- `go vet ./...`: catch common Go correctness issues.
- `go build ./...`: verify all packages compile.
- `xcaddy build --output ./dist/caddy --with github.com/stdpi/cema=.`: build a Caddy binary with this plugin locally.

CI runs tests, vet, xcaddy build, and a module smoke test from `.github/workflows/xcaddy.yml`.

## Coding Style & Naming Conventions

Use idiomatic Go and run `gofmt` on changed Go files. Keep package names short and lowercase. Exported types and functions need clear comments, especially Caddy modules and interfaces. Preserve Caddy module IDs exactly, such as `cema`, `tls.get_certificate.cema`, and `http.handlers.cema_api`.

## Testing Guidelines

Tests use Go’s standard `testing` package. Place tests beside code as `*_test.go`; prefer table-driven tests for branching behavior. Cover storage, API handlers, Caddy manager behavior, and error paths. Use `t.TempDir()` for storage tests and avoid network dependencies unless using `httptest`.

## Commit & Pull Request Guidelines

Current history uses short imperative commit subjects, for example `initial cema caddy modules` and `fix xcaddy workflow go version`. Keep commits focused. Pull requests should describe behavior changes, config impact, validation commands, and any remaining WIP such as ACME, DNS, TLS-ALPN, or TCP challenge support.

## Security & Configuration Tips

Do not commit real API tokens or DNS credentials. Use Caddy environment placeholders such as `{$CEMA_TOKEN}` and `{$CF_API_TOKEN}`. Treat manager API responses as sensitive because certificate bundles currently include private keys.
