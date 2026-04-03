package api

import (
	"certd-go/internal/models"
	"certd-go/internal/store"
	"certd-go/pkg/acme"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

type Server struct {
	store   *store.Store
	certDir string
	mux     *http.ServeMux
}

func NewServer(s *store.Store, certDir string) *Server {
	srv := &Server{
		store:   s,
		certDir: certDir,
		mux:     http.NewServeMux(),
	}
	srv.routes()
	return srv
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/certs", s.listCerts)
	s.mux.HandleFunc("GET /api/certs/{id}", s.getCert)
	s.mux.HandleFunc("POST /api/certs", s.createCert)
	s.mux.HandleFunc("PUT /api/certs/{id}", s.updateCert)
	s.mux.HandleFunc("DELETE /api/certs/{id}", s.deleteCert)
	s.mux.HandleFunc("GET /api/certs/{id}/download", s.downloadCert)

	s.mux.HandleFunc("GET /", s.serveIndex)
	s.mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("web/css"))))
	s.mux.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("web/js"))))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "web/index.html")
}

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.List()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}

func (s *Server) getCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	id, _ = url.QueryUnescape(id)

	cert, err := s.store.Get(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if cert == nil {
		http.Error(w, "not found", 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cert)
}

type CreateCertRequest struct {
	Domain      string   `json:"domain"`
	AltNames    []string `json:"alt_names"`
	Provider    string   `json:"provider"`
	DNSProvider string   `json:"dns_provider"`
	CertType    string   `json:"cert_type"`
	Email       string   `json:"email"`
	APIKey      string   `json:"api_key"`
	APISecret   string   `json:"api_secret"`
}

func (s *Server) createCert(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "empty body", 400)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer r.Body.Close()

	var req CreateCertRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if req.Domain == "" {
		http.Error(w, "domain is required", 400)
		return
	}

	certPEM, keyPEM, err := s.issueCert(req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	certInfo, err := acme.GetCertInfo(certPEM)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	meta := &models.CertMeta{
		Domain:      req.Domain,
		AltNames:    req.AltNames,
		Provider:    req.Provider,
		DNSProvider: req.DNSProvider,
		CertType:    req.CertType,
		NotBefore:   certInfo.NotBefore,
		NotAfter:    certInfo.NotAfter,
		SerialNum:   certInfo.SerialNumber,
		Issuer:      certInfo.Issuer,
		Fingerprint: certInfo.Fingerprint,
	}

	if err := s.saveCertFiles(meta.ID, certPEM, keyPEM); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if err := s.store.Create(meta); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(meta)
}

func (s *Server) issueCert(req CreateCertRequest) ([]byte, []byte, error) {
	switch req.Provider {
	case "selfsigned", "letsencrypt":
		return acme.GenerateSelfSigned(req.Domain, req.AltNames)
	default:
		return nil, nil, fmt.Errorf("provider %s not implemented yet", req.Provider)
	}
}

func (s *Server) saveCertFiles(id string, certPEM, keyPEM []byte) error {
	domainPath := filepath.Join(s.certDir, id)
	if err := os.MkdirAll(domainPath, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(domainPath, "cert.pem"), certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(domainPath, "key.pem"), keyPEM, 0600); err != nil {
		return err
	}
	return nil
}

type UpdateCertRequest struct {
	Project string `json:"project"`
	Owner   string `json:"owner"`
	Notes   string `json:"notes"`
}

func (s *Server) updateCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	id, _ = url.QueryUnescape(id)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	var req UpdateCertRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	cert, err := s.store.Get(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if cert == nil {
		http.Error(w, "not found", 404)
		return
	}

	cert.Project = req.Project
	cert.Owner = req.Owner
	cert.Notes = req.Notes

	if err := s.store.Update(cert); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cert)
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	id, _ = url.QueryUnescape(id)

	if err := s.store.Delete(id); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	domainPath := filepath.Join(s.certDir, id)
	os.RemoveAll(domainPath)

	w.WriteHeader(204)
}

func (s *Server) downloadCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	id, _ = url.QueryUnescape(id)

	cert, err := s.store.Get(id)
	if err != nil || cert == nil {
		http.Error(w, "not found", 404)
		return
	}

	certPEM, err := os.ReadFile(filepath.Join(s.certDir, id, "cert.pem"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	keyPEM, err := os.ReadFile(filepath.Join(s.certDir, id, "key.pem"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.tar", id))
	w.Header().Set("Content-Type", "application/octet-stream")

	fmt.Fprintf(w, "Certificate: %s\nKey: %s\n", certPEM, keyPEM)
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
