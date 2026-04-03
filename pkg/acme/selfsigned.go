package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func GenerateSelfSigned(domain string, altNames []string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	isWildcard := strings.HasPrefix(domain, "*.")
	dnsNames := altNames
	if isWildcard {
		rootDomain := strings.TrimPrefix(domain, "*.")
		hasRoot := false
		for _, n := range altNames {
			if n == rootDomain {
				hasRoot = true
				break
			}
		}
		if !hasRoot {
			dnsNames = append([]string{rootDomain}, altNames...)
		}
		dnsNames = append(dnsNames, domain)
	} else {
		dnsNames = append([]string{domain}, altNames...)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM, nil
}

func ParseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func GetCertInfo(certPEM []byte) (*CertInfo, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}

	info := &CertInfo{
		Domain:       cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
		Fingerprint:  fmt.Sprintf("%X", sha256.Sum256(cert.Raw)),
		DNSNames:     cert.DNSNames,
		SelfSigned:   cert.Subject.String() == cert.Issuer.String(),
		Expired:      time.Now().After(cert.NotAfter),
	}
	info.ValidDays = int(time.Until(cert.NotAfter).Hours() / 24)

	return info, nil
}

type CertInfo struct {
	Domain       string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
	Fingerprint  string
	DNSNames     []string
	SelfSigned   bool
	Expired      bool
	ValidDays    int
}

func DownloadCertFromHost(domain string) ([]*CertInfo, error) {
	conn, err := tls.Dial("tcp", domain+":443", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var results []*CertInfo

	for _, cert := range state.PeerCertificates {
		info, err := GetCertInfo(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
		if err != nil {
			continue
		}
		results = append(results, info)
	}

	return results, nil
}
