package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// Using the stable raw file URLs from the official GitHub mirror of Chromium.
	textprotoURL = "https://raw.githubusercontent.com/chromium/chromium/main/net/data/ssl/chrome_root_store/root_store.textproto"
	certsURL     = "https://raw.githubusercontent.com/chromium/chromium/main/net/data/ssl/chrome_root_store/root_store.certs"
)

// downloadRaw fetches a URL and returns its raw body content.
func downloadRaw(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status for %s: %s", url, resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func main() {
	// 1. Download and parse the textproto file to get the set of trusted SHA-256 hashes.
	fmt.Printf("Downloading trusted hashes from %s...\n", textprotoURL)
	textprotoData, err := downloadRaw(textprotoURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	trustedHashes := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(textprotoData)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Look for lines like: sha256_hex: "..."
		if strings.HasPrefix(line, "sha256_hex:") {
			parts := strings.SplitN(line, "\"", 2)
			if len(parts) == 2 {
				hash := strings.TrimRight(parts[1], "\"")
				trustedHashes[hash] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading textproto data: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d trusted root certificate hashes.\n", len(trustedHashes))

	// 2. Download the certificate bundle file.
	fmt.Printf("Downloading certificates from %s...\n", certsURL)
	certsData, err := downloadRaw(certsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// 3. Create the output PEM file.
	currentTime := time.Now()
	outputFileName := "Chrome-PEM-" + currentTime.Format("02012006") + ".pem"

	outFile, err := os.Create(outputFileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	// 4. Loop through the certsData, decoding one PEM block at a time.
	certsProcessed := 0
	certsWritten := 0
	data := certsData
	for len(data) > 0 {
		// pem.Decode will find the next PEM formatted block (e.g. -----BEGIN CERTIFICATE-----)
		// in the data and return it, along with the rest of the data.
		block, rest := pem.Decode(data)
		if block == nil {
			// This means no more PEM blocks were found.
			break
		}
		certsProcessed++

		// We are only interested in certificate blocks.
		if block.Type == "CERTIFICATE" {
			// Calculate the SHA-256 hash of the certificate's raw DER data.
			hash := sha256.Sum256(block.Bytes)
			hashHex := fmt.Sprintf("%x", hash)

			// If the hash is in our trusted set, write the original PEM block to the file.
			if trustedHashes[hashHex] {
				if err := pem.Encode(outFile, block); err != nil {
					fmt.Fprintf(os.Stderr, "Error encoding PEM block: %v\n", err)
					os.Exit(1)
				}
				certsWritten++
			}
		}

		// Continue the loop with the rest of the data.
		data = rest
	}

	fmt.Printf("Processed %d PEM blocks, wrote %d trusted certificates to %s\n", certsProcessed, certsWritten, outputFileName)
}
