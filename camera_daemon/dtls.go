package main

import 	(
	"fmt"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"crypto/sha256"
)

var CRT_FILE_PATH = "/etc/camera_server/static/certificate/danil_petrov.crt"
var KEY_FILE_PATH = "/etc/camera_server/static/certificate/danil_petrov.key"

func (client *WebrtcConnection) OpenCert() error {

	caCert, err := ioutil.ReadFile(CRT_FILE_PATH)
	if err != nil {
		fmt.Printf("Error opening cert file %s, Error: %s\n",
			CRT_FILE_PATH, err.Error())

		return err
	}

	block, _ := pem.Decode([]byte(caCert))
	if block == nil {
		fmt.Printf("failed to parse certificate PEM\n")

		return err
	}

	client.cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("failed to parse certificate: %s\n" + err.Error())

		return err
	}

	return nil
}

func FingerPrintCertificate(cert *x509.Certificate) string {
	var buf bytes.Buffer


	if cert == nil {
		fmt.Printf("Bad certificate\n")

		return ""
	}

	fingerprint := sha256.Sum256(cert.Raw)

	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}
