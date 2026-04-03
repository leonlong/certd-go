package aliyun

import (
	"context"
)

type Provider struct{}

func NewProvider(accessKey, secretKey string) (*Provider, error) {
	return &Provider{}, nil
}

func (p *Provider) Name() string { return "aliyun" }
func (p *Provider) Present(ctx context.Context, domain, token string) error {
	return nil
}
func (p *Provider) CleanUp(ctx context.Context, domain, token string) error {
	return nil
}
