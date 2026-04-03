package trustasia

import (
	"context"
)

type Provider struct{}

func NewProvider(apiKey, apiSecret, partnerID string) *Provider {
	return &Provider{}
}

func (p *Provider) Name() string { return "trustasia" }

func (p *Provider) Issue(ctx context.Context, domain string, altNames []string) (*IssuedCert, error) {
	return nil, nil
}

type IssuedCert struct {
	Domain    string
	CertPEM   []byte
	KeyPEM    []byte
	CaCertPEM []byte
	Issuer    string
}
