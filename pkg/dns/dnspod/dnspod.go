package dnspod

import (
	"context"
)

type Provider struct{}

func NewProvider(loginToken string) (*Provider, error) {
	return &Provider{}, nil
}

func (p *Provider) Name() string { return "dnspod" }
func (p *Provider) Present(ctx context.Context, domain, token string) error {
	return nil
}
func (p *Provider) CleanUp(ctx context.Context, domain, token string) error {
	return nil
}
