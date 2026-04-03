package certutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func ParseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ValidateCert(certPEM, keyPEM []byte, domain string) error {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate is expired")
	}

	if cert.Subject.CommonName != domain {
		return fmt.Errorf("certificate domain mismatch: expected %s, got %s", domain, cert.Subject.CommonName)
	}

	for _, dnsName := range cert.DNSNames {
		if dnsName == domain {
			return nil
		}
	}

	return fmt.Errorf("domain %s not found in certificate SANs", domain)
}

func DownloadCert(domain string) ([]*CertInfo, error) {
	conn, err := tls.Dial("tcp", domain+":443", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var results []*CertInfo

	for _, cert := range state.PeerCertificates {
		info := &CertInfo{
			Domain:   cert.Subject.CommonName,
			Issuer:   cert.Issuer.CommonName,
			DNSNames: cert.DNSNames,
		}
		results = append(results, info)
	}

	return results, nil
}

type CertInfo struct {
	Domain    string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	DNSNames  []string
}

func CheckOCSP(certPEM []byte) (string, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return "", err
	}

	ocspURL := ""
	for _, ext := range cert.Extensions {
		if strings.Contains(ext.Id.String(), "1.3.6.1.5.5.7.1.1") {
			ocspURL = string(ext.Value)
			break
		}
	}

	if ocspURL == "" {
		return "", fmt.Errorf("no OCSP URL found")
	}

	resp, err := http.Get(ocspURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return resp.Status, nil
}
