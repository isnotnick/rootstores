package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var certificateCounter int

var certificateStorePEM strings.Builder

var appleURL = "https://api.github.com/repos/apple-oss-distributions/security_certificates/contents/certificates/roots/"

func main() {
	currentTime := time.Now()

	apiUrl := appleURL
	response, err := http.Get(apiUrl)
	if err != nil {
		log.Fatal("Cannot open URL")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.Fatal("Failed to retrieve contents. Status: %d", response.StatusCode)
	}

	var files []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"download_url"`
	}

	if err := json.NewDecoder(response.Body).Decode(&files); err != nil {
		log.Fatal("Error processing JSON response")
	}

	for _, file := range files {
		if file.DownloadURL != "" {
			certificateCounter++
			certificateClient := &http.Client{
				Timeout: 15 * time.Second,
			}

			certificateDownload, err := certificateClient.Get(file.DownloadURL)
			if err != nil {
				log.Fatal(err)
			}
			defer certificateDownload.Body.Close()

			certificateResponseBytes, err := ioutil.ReadAll(certificateDownload.Body)
			if err != nil {
				log.Fatal("Error grabbing cert: ", err)
			}

			certificatePEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certificateResponseBytes,
			})
			certificateStorePEM.WriteString(string(certificatePEM))
		}
	}

	fmt.Println("Certificates found: ", certificateCounter)
	err = ioutil.WriteFile("Apple-PEM-"+currentTime.Format("02012006")+".pem", []byte(certificateStorePEM.String()), 0755)
	if err != nil {
		log.Fatal("Error writing PEM file. ", err)
	}
}

func ghRepoFileFetch() error {
	apiUrl := appleURL
	response, err := http.Get(apiUrl)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to retrieve contents. Status: %d", response.StatusCode)
	}

	var files []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"download_url"`
	}

	if err := json.NewDecoder(response.Body).Decode(&files); err != nil {
		return err
	}

	for _, file := range files {
		if file.DownloadURL != "" {
			certificateCounter++
			certificateClient := &http.Client{
				Timeout: 15 * time.Second,
			}

			certificateDownload, err := certificateClient.Get(file.DownloadURL)
			if err != nil {
				log.Fatal(err)
			}
			defer certificateDownload.Body.Close()

			certificateResponseBytes, err := ioutil.ReadAll(certificateDownload.Body)
			if err != nil {
				log.Fatal("Error grabbing cert: ", err)
			}

			certificatePEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certificateResponseBytes,
			})
			certificateStorePEM.WriteString(string(certificatePEM))
		}
	}
	return nil
}
