package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"

	"github.com/caddyserver/certmagic"
)

// CertMagicStore stores CEMA certificate records in Caddy/CertMagic storage.
type CertMagicStore struct {
	storage certmagic.Storage
	prefix  string
}

// NewCertMagicStore creates a store backed by Caddy's configured storage.
func NewCertMagicStore(storage certmagic.Storage, prefix string) (*CertMagicStore, error) {
	if storage == nil {
		return nil, errors.New("storage is nil")
	}
	if prefix == "" {
		prefix = "cema/certificates"
	}
	return &CertMagicStore{storage: storage, prefix: prefix}, nil
}

// Get loads a certificate record by domain.
func (cms *CertMagicStore) Get(ctx context.Context, domain string) (*CertificateRecord, error) {
	key, err := cms.key(domain)
	if err != nil {
		return nil, err
	}
	data, err := cms.storage.Load(ctx, key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load record: %w", err)
	}
	var record CertificateRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode record: %w", err)
	}
	return &record, nil
}

// Put stores a certificate record.
func (cms *CertMagicStore) Put(ctx context.Context, record *CertificateRecord) error {
	if record == nil {
		return errors.New("record is nil")
	}
	key, err := cms.key(record.Domain)
	if err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	if err := cms.storage.Store(ctx, key, data); err != nil {
		return fmt.Errorf("store record: %w", err)
	}
	return nil
}

// Delete removes a certificate record.
func (cms *CertMagicStore) Delete(ctx context.Context, domain string) error {
	key, err := cms.key(domain)
	if err != nil {
		return err
	}
	if err := cms.storage.Delete(ctx, key); errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("delete record: %w", err)
	}
	return nil
}

func (cms *CertMagicStore) key(domain string) (string, error) {
	safe, err := SafeDomainKey(domain)
	if err != nil {
		return "", err
	}
	return path.Join(cms.prefix, safe+".json"), nil
}
