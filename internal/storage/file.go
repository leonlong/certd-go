package storage

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type FileStorage struct {
	basePath string
}

func NewFileStorage(path string) *FileStorage {
	return &FileStorage{basePath: path}
}

func (s *FileStorage) Save(domain string, certPEM, keyPEM, caCertPEM []byte) error {
	domainPath := filepath.Join(s.basePath, domain)
	if err := os.MkdirAll(domainPath, 0755); err != nil {
		return err
	}

	certPath := filepath.Join(domainPath, "cert.pem")
	keyPath := filepath.Join(domainPath, "key.pem")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	if len(caCertPEM) > 0 {
		caPath := filepath.Join(domainPath, "ca.pem")
		if err := os.WriteFile(caPath, caCertPEM, 0644); err != nil {
			return fmt.Errorf("failed to write ca cert: %w", err)
		}
	}

	fullChainPath := filepath.Join(domainPath, "fullchain.pem")
	if len(caCertPEM) > 0 {
		fullChain := append(certPEM, caCertPEM...)
		if err := os.WriteFile(fullChainPath, fullChain, 0644); err != nil {
			return fmt.Errorf("failed to write fullchain: %w", err)
		}
	}

	return nil
}

func (s *FileStorage) Load(domain string) (*CertFiles, error) {
	certPath := filepath.Join(s.basePath, domain, "cert.pem")
	keyPath := filepath.Join(s.basePath, domain, "key.pem")
	caPath := filepath.Join(s.basePath, domain, "ca.pem")
	fullChainPath := filepath.Join(s.basePath, domain, "fullchain.pem")

	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cert not found: %w", err)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	ca, _ := os.ReadFile(caPath)
	fullchain, _ := os.ReadFile(fullChainPath)

	return &CertFiles{
		Domain:       domain,
		CertPEM:      cert,
		KeyPEM:       key,
		CaCertPEM:    ca,
		FullChainPEM: fullchain,
	}, nil
}

func (s *FileStorage) Exists(domain string) bool {
	certPath := filepath.Join(s.basePath, domain, "cert.pem")
	_, err := os.Stat(certPath)
	return err == nil
}

func (s *FileStorage) List() ([]string, error) {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, err
	}

	var domains []string
	for _, entry := range entries {
		if entry.IsDir() {
			domains = append(domains, entry.Name())
		}
	}
	return domains, nil
}

func (s *FileStorage) Delete(domain string) error {
	domainPath := filepath.Join(s.basePath, domain)
	return os.RemoveAll(domainPath)
}

type CertFiles struct {
	Domain       string
	CertPEM      []byte
	KeyPEM       []byte
	CaCertPEM    []byte
	FullChainPEM []byte
}

type Storage interface {
	Save(domain string, certPEM, keyPEM, caCertPEM []byte) error
	Load(domain string) (*CertFiles, error)
	Exists(domain string) bool
	List() ([]string, error)
	Delete(domain string) error
}

var _ Storage = (*FileStorage)(nil)
