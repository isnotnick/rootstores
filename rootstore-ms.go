package main

import (
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

//	We're just going to cheat for now. Use Rob's Github repo...
//	To do...Go .cab file reader?
var msURL = "https://github.com/robstradling/authroot.stl/tree/master/crt"
var msRawURL = "https://raw.githubusercontent.com/robstradling/authroot.stl/master/crt/"

func main() {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	currentTime := time.Now()

	response, err := client.Get(msURL)
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
	err = ioutil.WriteFile("MS-PEM-"+currentTime.Format("02012006")+".pem", []byte(certificateStorePEM.String()), 0755)
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
			msRawURL := strings.Replace(href, "blob", "raw", 1)
			certificateDownload, err := certificateClient.Get("https://github.com" + msRawURL)

			if err != nil {
				log.Fatal(err)
			}
			defer certificateDownload.Body.Close()

			certificateResponseBytes, err := ioutil.ReadAll(certificateDownload.Body)
			if err != nil {
				log.Fatal("Error grabbing cert: ", err)
			}

			certificateStorePEM.WriteString(string(certificateResponseBytes))
		}
	}
}
