package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrNotFound means no certificate record exists for domain.
var ErrNotFound = errors.New("certificate not found")

// FileStore stores certificate records as JSON files.
type FileStore struct {
	dir string
	mu  sync.RWMutex
}

// NewFileStore creates a file-backed certificate store.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

// Get loads a certificate record by domain.
func (fs *FileStore) Get(ctx context.Context, domain string) (*CertificateRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	path, err := fs.path(domain)
	if err != nil {
		return nil, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read record: %w", err)
	}

	var record CertificateRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode record: %w", err)
	}
	return &record, nil
}

// Put stores a certificate record.
func (fs *FileStore) Put(ctx context.Context, record *CertificateRecord) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}
	if record == nil {
		return errors.New("record is nil")
	}
	path, err := fs.path(record.Domain)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp record: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit record: %w", err)
	}
	return nil
}

// Delete removes a certificate record.
func (fs *FileStore) Delete(ctx context.Context, domain string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}
	path, err := fs.path(domain)
	if err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("delete record: %w", err)
	}
	return nil
}

func (fs *FileStore) path(domain string) (string, error) {
	name, err := safeDomainFileName(domain)
	if err != nil {
		return "", err
	}
	return filepath.Join(fs.dir, name+".json"), nil
}

// SafeDomainKey normalizes a domain into a safe storage key component.
func SafeDomainKey(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return "", errors.New("domain is required")
	}
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == '*' {
			continue
		}
		return "", fmt.Errorf("invalid domain character %q", r)
	}
	return strings.ReplaceAll(domain, "*", "_wildcard_"), nil
}

func safeDomainFileName(domain string) (string, error) {
	return SafeDomainKey(domain)
}
