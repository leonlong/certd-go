package certchain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ChainBuilder struct {
	httpClient *http.Client
}

func NewChainBuilder() *ChainBuilder {
	return &ChainBuilder{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (cb *ChainBuilder) BuildFullChain(serverCertPEM []byte) ([]byte, error) {
	serverCert, err := ParseCertificate(serverCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}

	issuerCert, err := cb.fetchIssuerCertificate(serverCert)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer certificate: %w", err)
	}

	var chainPEM []byte
	chainPEM = append(chainPEM, serverCertPEM...)

	if issuerCert != nil {
		issuerCertPEM := CertToPEM(issuerCert)
		chainPEM = append(chainPEM, issuerCertPEM...)

		if !isSelfSigned(issuerCert) {
			rootCert, err := cb.fetchRootCertificate(issuerCert)
			if err == nil && rootCert != nil {
				rootCertPEM := CertToPEM(rootCert)
				chainPEM = append(chainPEM, rootCertPEM...)
			}
		}
	}

	return chainPEM, nil
}

func (cb *ChainBuilder) fetchIssuerCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	if isSelfSigned(cert) {
		return nil, nil
	}

	issuerCert, err := cb.fetchFromAIA(cert)
	if err == nil && issuerCert != nil {
		return issuerCert, nil
	}

	issuerCert, err = cb.fetchKnownIssuer(cert.Issuer.String())
	if err == nil && issuerCert != nil {
		return issuerCert, nil
	}

	return nil, fmt.Errorf("could not fetch issuer certificate for %s", cert.Issuer.String())
}

func (cb *ChainBuilder) fetchFromAIA(cert *x509.Certificate) (*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("no AIA information available")
	}

	for _, url := range cert.IssuingCertificateURL {
		certPEM, err := cb.downloadCert(url)
		if err != nil {
			continue
		}

		issuerCert, err := ParseCertificate(certPEM)
		if err != nil {
			continue
		}

		if issuerCert.CheckSignatureFrom(cert) == nil {
			return issuerCert, nil
		}
	}

	return nil, fmt.Errorf("failed to fetch issuer from AIA")
}

func (cb *ChainBuilder) downloadCert(url string) ([]byte, error) {
	resp, err := cb.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	buf := make([]byte, 0, 4096)
	buf = make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return buf[:n], nil
}

func (cb *ChainBuilder) fetchRootCertificate(intermediateCert *x509.Certificate) (*x509.Certificate, error) {
	if len(intermediateCert.IssuingCertificateURL) == 0 {
		if isWellKnownRoot(intermediateCert.Issuer.String()) {
			return nil, nil
		}
		return nil, fmt.Errorf("no AIA information for root")
	}

	for _, url := range intermediateCert.IssuingCertificateURL {
		certPEM, err := cb.downloadCert(url)
		if err != nil {
			continue
		}

		rootCert, err := ParseCertificate(certPEM)
		if err != nil {
			continue
		}

		if isSelfSigned(rootCert) {
			return rootCert, nil
		}
	}

	return nil, fmt.Errorf("could not fetch root certificate")
}

func (cb *ChainBuilder) fetchKnownIssuer(issuerDN string) (*x509.Certificate, error) {
	issuerDN = strings.TrimSpace(issuerDN)

	if strings.Contains(issuerDN, "Let's Encrypt") || strings.Contains(issuerDN, "R3") {
		return FetchLetsEncryptChain(), nil
	}

	if strings.Contains(issuerDN, "DigiCert") {
		return FetchDigiCertRoot(), nil
	}

	if strings.Contains(issuerDN, "GlobalSign") {
		return FetchGlobalSignRoot(), nil
	}

	if strings.Contains(issuerDN, "Sectigo") || strings.Contains(issuerDN, "USERTrust") {
		return FetchSectigoChain(), nil
	}

	if strings.Contains(issuerDN, "Amazon") {
		return FetchAmazonRoot(), nil
	}

	return nil, fmt.Errorf("unknown issuer: %s", issuerDN)
}

func ParseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

func CertToPEM(cert *x509.Certificate) []byte {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(pemBlock)
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func isWellKnownRoot(issuerDN string) bool {
	roots := []string{
		"DigiCert Global Root",
		"DigiCert Global Root G2",
		"GlobalSign",
		"GlobalSign Root CA",
		"Amazon Root CA 1",
		"Amazon Root CA 3",
		"ISRG Root X1",
		"Let's Encrypt",
	}

	for _, root := range roots {
		if strings.Contains(issuerDN, root) {
			return true
		}
	}
	return false
}

func (cb *ChainBuilder) ValidateChain(chainPEM []byte) error {
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(chainPEM)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
		chainPEM = rest
	}

	if len(certs) < 1 {
		return fmt.Errorf("no certificates in chain")
	}

	serverCert := certs[0]

	if len(certs) == 1 {
		if !isSelfSigned(serverCert) {
			return fmt.Errorf("incomplete chain: only server certificate, missing issuer")
		}
		return nil
	}

	for i := 0; i < len(certs)-1; i++ {
		err := certs[i+1].CheckSignatureFrom(certs[i])
		if err != nil {
			return fmt.Errorf("signature verification failed at position %d: %w", i+1, err)
		}
	}

	_ = serverCert

	return nil
}

func (cb *ChainBuilder) GetChainInfo(chainPEM []byte) ([]ChainInfo, error) {
	var infos []ChainInfo

	for {
		block, rest := pem.Decode(chainPEM)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		info := ChainInfo{
			Subject:      cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			IsCA:         cert.IsCA,
			IsSelfSigned: isSelfSigned(cert),
		}
		infos = append(infos, info)
		chainPEM = rest
	}

	return infos, nil
}

type ChainInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	IsCA         bool
	IsSelfSigned bool
}
