# certd-go

极简证书申请管理工具

## 支持

### CA Providers
- **Let's Encrypt** (ACME协议, 支持http-01/dns-01挑战)
- **锐成** (RA, Chinassl)
- **亚洲诚信** (TrustAsia)
- **GlobalSign**

### DNS Providers
- 阿里云
- 腾讯云
- DNSPod
- Cloudflare

## 安装

```bash
go install ./cmd/cli
```

## 使用

```bash
# 申请证书
certd-go issue --domain example.com --provider letsencrypt --email admin@example.com

# 列出证书
certd-go list

# 查看证书信息
certd-go info example.com

# 验证证书
certd-go validate example.com

# 下载远程证书
certd-go download example.com

# 续期证书
certd-go renew example.com --provider letsencrypt

# 删除证书
certd-go delete example.com
```

## 配置

复制 `config.example.yaml` 为 `config.yaml` 并配置。

## License

MIT
