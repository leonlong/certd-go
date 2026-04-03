package ra

import (
	"context"
)

type Provider struct{}

func NewProvider(apiKey, apiSecret string) *Provider {
	return &Provider{}
}

func (p *Provider) Name() string { return "ra" }

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
