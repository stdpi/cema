// Package issuer issues certificates for daemon requests.
package issuer

import (
	"context"

	"github.com/stdpi/cema/internal/store"
)

// CertificateRequest describes a certificate order.
type CertificateRequest struct {
	Domain string   `json:"domain"`
	SANs   []string `json:"sans,omitempty"`
	Force  bool     `json:"force,omitempty"`
}

// Issuer obtains or creates certificates for requests.
type Issuer interface {
	Issue(ctx context.Context, request CertificateRequest) (*store.CertificateRecord, error)
}
