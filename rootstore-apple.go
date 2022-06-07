package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

var certificateFiletypes = map[string]bool{
	".crt": true,
	".cer": true,
	".der": true,
}

var certificateCounter int

var certificateStorePEM strings.Builder

var appleURL = "https://opensource.apple.com/source/security_certificates/security_certificates-55188.80.4/certificates/roots/"

func main() {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	currentTime := time.Now()

	response, err := client.Get(appleURL)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	document, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.Fatal("Error loading HTTP response body. ", err)
	}

	document.Find("a").Each(checkCertificateLink)
	fmt.Println("Certificates found: ", certificateCounter)
	err = ioutil.WriteFile("Apple-PEM-"+currentTime.Format("02012006")+".pem", []byte(certificateStorePEM.String()), 0755)
	if err != nil {
		log.Fatal("Error writing PEM file. ", err)
	}
}

func checkCertificateLink(index int, element *goquery.Selection) {
	href, exists := element.Attr("href")
	if exists {
		if certificateFiletypes[filepath.Ext(href)] {
			certificateCounter++
			certificateClient := &http.Client{
				Timeout: 15 * time.Second,
			}

			certificateDownload, err := certificateClient.Get(appleURL + href)
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
}
