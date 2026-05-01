// Package store persists certificate records for CEMA.
package store

import (
	"context"
	"time"
)

// CertificateRecord is one stored certificate/key pair.
type CertificateRecord struct {
	Domain    string    `json:"domain"`
	SANs      []string  `json:"sans,omitempty"`
	BundlePEM string    `json:"bundle_pem"`
	CertPEM   string    `json:"cert_pem"`
	KeyPEM    string    `json:"key_pem"`
	NotAfter  time.Time `json:"not_after"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store reads and writes certificate records.
type Store interface {
	Get(ctx context.Context, domain string) (*CertificateRecord, error)
	Put(ctx context.Context, record *CertificateRecord) error
	Delete(ctx context.Context, domain string) error
}
