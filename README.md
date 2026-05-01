# CEMA

CEMA is a Caddy-native certificate coordination experiment. It lets one Caddy tier act as a certificate manager while other Caddy tiers fetch and locally cache certificates through Caddy's normal storage system.

The current code is MVP/WIP. It proves the Caddy module shape, manager/replica split, local storage integration, manager API, and delegated HTTP-01 challenge serving hook. Real public ACME issuance is still behind an issuer interface; the current issuer creates self-signed certificates so the full flow can be tested without a CA.

## Goals

- Keep certificate logic inside Caddy modules instead of running a separate daemon.
- Use Caddy/CertMagic storage through `ctx.Storage()`.
- Allow tier 1 replicas to keep serving cached certificates if tier 0 is unavailable.
- Prepare for delegated ACME challenges where replicas can answer HTTP-01/TLS-ALPN-01 traffic.
- Reuse Caddy DNS provider modules (`dns.providers.*`) for DNS-01 instead of maintaining a separate DNS ecosystem.

## Architecture

### Tier 0: manager

Tier 0 owns issuance, storage, renewal, and the manager API.

Responsibilities:

- issue or renew certificates
- store certificates in Caddy storage
- expose certificate API through `cema_api`
- accept delegated challenge tasks
- later: run real ACME and DNS-01 through Caddy DNS providers

### Tier 1: replica

Tier 1 serves application traffic and gets certificates from tier 0.

Responsibilities:

- use `tls.get_certificate.cema`
- fetch certificates from manager
- store fetched certificates in local Caddy storage
- serve cached certs while manager is down
- serve HTTP-01 delegated challenges through `cema_challenge`
- later: TLS-ALPN-01 and TCP challenge relay

## Build

Install `xcaddy`, then build Caddy with CEMA:

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/stdpi/cema=.
```

Build with DNS providers:

```sh
xcaddy build \
  --with github.com/stdpi/cema=. \
  --with github.com/caddy-dns/cloudflare \
  --with github.com/caddy-dns/route53 \
  --with github.com/caddy-dns/digitalocean
```

## Tier 0 Caddyfile

```caddy
{
	storage file_system {
		root /var/lib/caddy
	}

	cema manager {
		token {$CEMA_TOKEN}
		storage_prefix cema/certificates
	}
}

manager.acme.co {
	cema_api
}
```

## Tier 1 Caddyfile

```caddy
{
	cema replica {
		manager https://manager.acme.co
		token {$CEMA_TOKEN}

		challenges {
			http
			# tls_alpn WIP
			# tcp WIP
		}
	}

	tls {
		get_certificate cema
	}
}

*.acme.co {
	cema_challenge
	reverse_proxy localhost:3000
}
```

## Modules

- `cema`: Caddy app for manager/replica state.
- `tls.get_certificate.cema`: certificate manager used by Caddy TLS automation.
- `http.handlers.cema_api`: manager API handler.
- `http.handlers.cema_challenge`: HTTP-01 delegated challenge handler.
- `tls.get_certificate.central_daemon`: older external-daemon getter kept for experiments.

## Manager API

When exposed with `cema_api`:

```http
GET /health
POST /certificates/request
GET /certificates/{domain}
DELETE /certificates/{domain}
PUT /challenges/http-01/{token}
```

Auth:

- `Authorization: Bearer <token>`
- or `X-CEMA-Token: <token>`

Request certificate:

```sh
curl -H "Authorization: Bearer $CEMA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' \
  https://manager.acme.co/certificates/request
```

Add HTTP-01 challenge task:

```sh
curl -X PUT -H "Authorization: Bearer $CEMA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","token":"abc","key_auth":"abc.thumbprint"}' \
  https://replica.acme.co/challenges/http-01/abc
```

## Current Limitations

- Public ACME is not wired yet; self-signed issuer is used for MVP.
- DNS provider config is not loaded yet, but intended path is Caddy `dns.providers.*`.
- HTTP-01 serving exists, but ACME order creation does not yet push tasks automatically.
- TLS-ALPN-01 and TCP challenge relay are planned only.
- Manager API currently returns PEM bundle containing certificate and private key; use mTLS/private networks in real deployments.

## Development

Run checks:

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./...
```
