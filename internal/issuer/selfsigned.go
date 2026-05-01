package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/stdpi/cema/internal/store"
)

// SelfSignedIssuer creates local self-signed certificates for MVP/dev use.
type SelfSignedIssuer struct {
	validFor time.Duration
}

// NewSelfSignedIssuer returns an issuer for local MVP certificates.
func NewSelfSignedIssuer() *SelfSignedIssuer {
	return &SelfSignedIssuer{validFor: 90 * 24 * time.Hour}
}

// Issue creates a new self-signed certificate.
func (ssi *SelfSignedIssuer) Issue(ctx context.Context, request CertificateRequest) (*store.CertificateRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	names := uniqueNames(request.Domain, request.SANs)
	if len(names) == 0 {
		return nil, fmt.Errorf("domain is required")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.Add(ssi.validFor)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: names[0],
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, name)
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	now := time.Now()

	return &store.CertificateRecord{
		Domain:    names[0],
		SANs:      names[1:],
		BundlePEM: certPEM + keyPEM,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		NotAfter:  notAfter,
		UpdatedAt: now,
	}, nil
}

func uniqueNames(domain string, sans []string) []string {
	seen := make(map[string]struct{}, len(sans)+1)
	out := make([]string, 0, len(sans)+1)
	for _, name := range append([]string{domain}, sans...) {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
