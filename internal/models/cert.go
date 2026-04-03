package models

import "time"

type CertMeta struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`
	AltNames    []string `json:"alt_names,omitempty"`
	Provider    string   `json:"provider"`
	DNSProvider string   `json:"dns_provider"`
	CertType    string   `json:"cert_type"`
	Project     string   `json:"project,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Notes       string   `json:"notes,omitempty"`

	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SerialNum   string    `json:"serial_num"`
	Issuer      string    `json:"issuer"`
	Fingerprint string    `json:"fingerprint"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (c *CertMeta) IsExpired() bool {
	return time.Now().After(c.NotAfter)
}

func (c *CertMeta) ValidDays() int {
	if c.IsExpired() {
		return 0
	}
	return int(time.Until(c.NotAfter).Hours() / 24)
}

func (c *CertMeta) Status() string {
	if c.IsExpired() {
		return "expired"
	}
	days := c.ValidDays()
	if days <= 30 {
		return "expiring"
	}
	return "valid"
}
