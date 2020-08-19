package main

import (
	"encoding/pem"
	_ "encoding/pem"
	"fmt"
	"io/ioutil"
	_ "io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var certificateCounter int

var certificateStorePEM strings.Builder

var appleURL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

func main() {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	response, err := client.Get(appleURL)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	certificateResponseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal("Error grabbing certdata.txt: ", err)
	}

	certdataLines := strings.Split(string(certificateResponseBytes), "\n")

	var gotCertificate, gotServerAuth bool
	var singleCertificate strings.Builder

	for _, certDataLine := range certdataLines {
		if strings.Contains(certDataLine, "#") {
			continue
		} else if strings.Contains(certDataLine, "CKA_VALUE MULTILINE_OCTAL") {
			gotServerAuth = false
			gotCertificate = true
			singleCertificate.WriteString("\"")
			continue
		} else if gotCertificate && strings.Contains(certDataLine, "END") {
			gotCertificate = false

			gotServerAuth = true
			continue
		} else if gotCertificate {
			singleCertificate.WriteString(certDataLine)
		} else if strings.Contains(certDataLine, "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR") && gotServerAuth {
			gotServerAuth = false
			singleCertificate.WriteString("\"")
			finalsSingleCertificate, _ := strconv.Unquote(singleCertificate.String())
			certificatePEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte(finalsSingleCertificate),
			})
			certificateStorePEM.WriteString(string(certificatePEM))
			singleCertificate.Reset()
			certificateCounter++
			continue
		}
	}

	fmt.Println("Certificates found: ", certificateCounter)
	currentTime := time.Now()
	err = ioutil.WriteFile("Mozilla-PEM-"+currentTime.Format("02012006")+".pem", []byte(certificateStorePEM.String()), 0755)
	if err != nil {
		log.Fatal("Error writing PEM file. ", err)
	}
}
