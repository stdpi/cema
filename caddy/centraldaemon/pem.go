package centraldaemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

func certValidFor(cert *tls.Certificate, min time.Duration) bool {
	if cert == nil {
		return false
	}
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return false
		}
		leaf = parsed
	}
	if leaf == nil {
		return false
	}
	return time.Now().Add(min).Before(leaf.NotAfter)
}

func pemBundle(cert *tls.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}
	var out []byte
	for _, certDER := range cert.Certificate {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return out, nil
}
