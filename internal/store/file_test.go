package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFileStoreCRUD(t *testing.T) {
	t.Parallel()

	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}

	ctx := context.Background()
	record := &CertificateRecord{
		Domain:    "example.com",
		BundlePEM: "bundle",
		CertPEM:   "cert",
		KeyPEM:    "key",
		NotAfter:  time.Now().Add(time.Hour),
		UpdatedAt: time.Now(),
	}

	if err := fs.Put(ctx, record); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := fs.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.BundlePEM != record.BundlePEM {
		t.Fatalf("BundlePEM = %q, want %q", got.BundlePEM, record.BundlePEM)
	}

	if err := fs.Delete(ctx, "example.com"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	_, err = fs.Get(ctx, "example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestFileStoreRejectsUnsafeDomain(t *testing.T) {
	t.Parallel()

	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}

	_, err = fs.Get(context.Background(), "../bad")
	if err == nil {
		t.Fatal("Get() error = nil, want error")
	}
}
