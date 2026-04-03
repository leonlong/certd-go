package store

import (
	"certd-go/internal/models"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	mu    sync.RWMutex
	path  string
	certs map[string]*models.CertMeta
}

func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}

	s := &Store{
		path:  filepath.Join(dataDir, "certs.json"),
		certs: make(map[string]*models.CertMeta),
	}

	if err := s.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	var certs []*models.CertMeta
	if err := json.Unmarshal(data, &certs); err != nil {
		return err
	}

	for _, c := range certs {
		s.certs[c.ID] = c
	}

	return nil
}

func (s *Store) save() error {
	var certs []*models.CertMeta
	for _, c := range s.certs {
		certs = append(certs, c)
	}

	data, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.path, data, 0644)
}

func (s *Store) Create(cert *models.CertMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cert.ID = cert.Domain
	cert.CreatedAt = time.Now()
	cert.UpdatedAt = time.Now()

	s.certs[cert.ID] = cert
	return s.save()
}

func (s *Store) Get(id string) (*models.CertMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if cert, ok := s.certs[id]; ok {
		return cert, nil
	}
	return nil, nil
}

func (s *Store) List() ([]*models.CertMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var certs []*models.CertMeta
	for _, c := range s.certs {
		certs = append(certs, c)
	}
	return certs, nil
}

func (s *Store) Update(cert *models.CertMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.certs[cert.ID]; !ok {
		return nil
	}

	cert.UpdatedAt = time.Now()
	s.certs[cert.ID] = cert
	return s.save()
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.certs, id)
	return s.save()
}
