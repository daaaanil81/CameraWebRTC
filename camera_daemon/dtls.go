package main

/*
#cgo LDFLAGS: -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

*/
import "C"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pion/dtls/v2"
)

const (
	CRT_FILE_PATH            = "/etc/camera_server/static/certificate/danil_petrov.crt"
	EXTRACTOR_DTLS_SRTP      = "EXTRACTOR-dtls_srtp"
	KEY_FILE_PATH            = "/etc/camera_server/static/certificate/danil_petrov.key"
	MASTER_KEY_LEN           = 16
	MASTER_SALT_LEN          = 14
	NO                       = 0
	SESSION_KEY_LEN          = 16
	SESSION_SALT_LEN         = 14
	SRTP_AUTH_KEY_LEN        = 20
	SRTP_AUTH_TAG            = 10
	SRTP_MAX_MASTER_KEY_LEN  = 32
	SRTP_MAX_MASTER_SALT_LEN = 14
	YES                      = 1
)

//var PEM_FILE_PATH = "/etc/camera_server/static/certificate/danil_petrov.pem"

func LoadKeyAndCertificate() (*tls.Certificate, error) {
	privateKey, err := LoadKey(KEY_FILE_PATH)
	if err != nil {
		return nil, err
	}

	certificate, err := LoadCertificate(CRT_FILE_PATH)
	if err != nil {
		return nil, err
	}

	certificate.PrivateKey = privateKey

	return certificate, nil
}

func LoadKey(path string) (crypto.PrivateKey, error) {
	rawData, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(rawData)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("Error with key has suffix")
	}

	fmt.Println(block.Type)

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("Error with key parse PKCS8")
		}
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("Error with Read key parse ECP")
}

func LoadCertificate(path string) (*tls.Certificate, error) {
	rawData, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate

	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, errors.New("Error with read Certificate type")
		}

		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		rawData = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errors.New("Error with read Certificate len")
	}

	return &certificate, nil
}

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

func (dtls_data *DtlsConnectionData) InitKeys() {
	dtls_data.crypto_rtp = new(CryptoKeys)
	dtls_data.crypto_rtp.have_session_key = false
	dtls_data.crypto_rtp.index = 0
	dtls_data.crypto_rtcp = new(CryptoKeys)
	dtls_data.crypto_rtcp.have_session_key = false
	dtls_data.crypto_rtcp.index = 0
	dtls_data.decrypt = new(CryptoKeys)
	dtls_data.decrypt.have_session_key = false
	dtls_data.decrypt.index = 0
}

func (client *WebrtcConnection) DtlsProccess() error {
	dtls_data := client.dtls_data
	crypto_rtp := dtls_data.crypto_rtp
	crypto_rtcp := dtls_data.crypto_rtcp

	certificate, err := LoadKeyAndCertificate()
	if err != nil {
		return err
	}

	config := &dtls.Config{
		Certificates: []tls.Certificate{*certificate},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		InsecureSkipVerify: true,
	}

	fmt.Println("Opened certificate")

	dtls_data.dtlsConn, err = dtls.Client(client.connectionUDP, config)
	if err != nil {
		return err
	}

	fmt.Println("Client connection")

	srtpProfile, res := dtls_data.dtlsConn.SelectedSRTPProtectionProfile()
	if res == false {
		return errors.New("Error with Selected SRTP Protection Profile DTLS")
	}

	switch srtpProfile {
	case dtls.SRTP_AEAD_AES_128_GCM:
		fmt.Println("Choose SRTP_AEAD_AES_128_GCM")
	case dtls.SRTP_AES128_CM_HMAC_SHA1_80:
		fmt.Println("Choose ProtectionProfileAes128CmHmacSha1_80")
	default:
		return errors.New("Error with DTLS switch profile")
	}

	dtlsState := dtls_data.dtlsConn.ConnectionState()

	keyingMaterial, err := dtlsState.ExportKeyingMaterial(EXTRACTOR_DTLS_SRTP, nil, (MASTER_KEY_LEN*2)+(MASTER_SALT_LEN*2))
	if err != nil {
		return err
	}

	offset := 0
	clientKey := append([]byte{}, keyingMaterial[offset:offset+MASTER_KEY_LEN]...)
	offset += 2 * MASTER_KEY_LEN
	clientKey = append(clientKey, keyingMaterial[offset:offset+MASTER_SALT_LEN]...)

	copy(crypto_rtp.master_key[:], clientKey[0:MASTER_KEY_LEN])
	copy(crypto_rtp.master_salt[:], clientKey[MASTER_KEY_LEN:])

	copy(crypto_rtcp.master_key[:], clientKey[0:MASTER_KEY_LEN])
	copy(crypto_rtcp.master_salt[:], clientKey[MASTER_KEY_LEN:])

	DEBUG_MESSAGE_BLOCK("LocalMasterKey: ", crypto_rtp.master_key[:])
	DEBUG_MESSAGE_BLOCK("LocalMasterSalt: ", crypto_rtp.master_salt[:])

	return nil
}
