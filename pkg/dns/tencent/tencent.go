package tencent

import (
	"context"
)

type Provider struct{}

func NewProvider(secretID, secretKey string) (*Provider, error) {
	return &Provider{}, nil
}

func (p *Provider) Name() string { return "tencent" }
func (p *Provider) Present(ctx context.Context, domain, token string) error {
	return nil
}
func (p *Provider) CleanUp(ctx context.Context, domain, token string) error {
	return nil
}
