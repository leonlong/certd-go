package main

import (
	"certd-go/internal/storage"
	"certd-go/pkg/certchain"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: rebuild-chain <cert_dir> [domain]")
		fmt.Println("  <cert_dir>: Directory containing certificates")
		fmt.Println("  [domain]:   Optional specific domain to rebuild (rebuilds all if not specified)")
		os.Exit(1)
	}

	certDir := os.Args[1]
	domain := ""
	if len(os.Args) > 2 {
		domain = os.Args[2]
	}

	store := storage.NewFileStorage(certDir)
	chainBuilder := certchain.NewChainBuilder()

	var domains []string
	var err error

	if domain != "" {
		domains = []string{domain}
	} else {
		domains, err = store.List()
		if err != nil {
			fmt.Printf("Failed to list certificates: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Rebuilding certificate chains for %d certificate(s)...\n\n", len(domains))

	successCount := 0
	errorCount := 0

	for _, d := range domains {
		fmt.Printf("Processing %s...\n", d)

		certFiles, err := store.Load(d)
		if err != nil {
			fmt.Printf("  ✗ Failed to load certificate: %v\n", err)
			errorCount++
			continue
		}

		chainInfo, err := chainBuilder.GetChainInfo(certFiles.CertPEM)
		if err != nil {
			fmt.Printf("  ✗ Failed to get chain info: %v\n", err)
			errorCount++
			continue
		}

		fmt.Printf("  Current chain length: %d\n", len(chainInfo))

		fullChain, err := chainBuilder.BuildFullChain(certFiles.CertPEM)
		if err != nil {
			fmt.Printf("  ✗ Failed to build full chain: %v\n", err)
			errorCount++
			continue
		}

		newChainInfo, err := chainBuilder.GetChainInfo(fullChain)
		if err != nil {
			fmt.Printf("  ✗ Failed to get new chain info: %v\n", err)
			errorCount++
			continue
		}

		fmt.Printf("  New chain length: %d\n", len(newChainInfo))

		if len(newChainInfo) > len(chainInfo) {
			err = store.Save(d, certFiles.CertPEM, certFiles.KeyPEM, nil)
			if err != nil {
				fmt.Printf("  ✗ Failed to save certificate: %v\n", err)
				errorCount++
				continue
			}

			domainPath := certDir + "/" + d
			err = os.WriteFile(domainPath+"/fullchain.pem", fullChain, 0644)
			if err != nil {
				fmt.Printf("  ✗ Failed to save full chain: %v\n", err)
				errorCount++
				continue
			}

			fmt.Printf("  ✓ Successfully rebuilt certificate chain\n")
			fmt.Printf("    Chain: %s", chainInfo[0].Subject)
			for i, info := range chainInfo[1:] {
				fmt.Printf(" → %s", info.Subject)
				if (i+1)%3 == 0 {
					fmt.Printf("\n           ")
				}
			}
			fmt.Printf("\n\n")
			successCount++
		} else {
			fmt.Printf("  ℹ Chain already complete\n\n")
			successCount++
		}
	}

	fmt.Printf("=== Summary ===\n")
	fmt.Printf("Total certificates: %d\n", len(domains))
	fmt.Printf("Success: %d\n", successCount)
	fmt.Printf("Errors: %d\n", errorCount)

	if errorCount > 0 {
		os.Exit(1)
	}
}
