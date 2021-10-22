package main

/*
#cgo LDFLAGS: -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

*/
import "C"

import 	(
	"fmt"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"crypto/sha256"
	"unsafe"
	"errors"
)

var (
	YES = 1
	NO  = 0
)

var CRT_FILE_PATH = "/etc/camera_server/static/certificate/danil_petrov.crt"
var KEY_FILE_PATH = "/etc/camera_server/static/certificate/danil_petrov.key"
var PEM_FILE_PATH = "/etc/camera_server/static/certificate/danil_petrov.pem"

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

func GenericCiphers() string {
	return "SRTP_AES128_CM_SHA1_80"
}

func (client *WebrtcConnection) SSL_CTX_new() error {
	client.ssl_ctx = C.SSL_CTX_new(C.DTLS_client_method())

	if client.ssl_ctx == nil {
		return errors.New("Error in SSL_CTX_new")
	}

	fmt.Println("Success with SSL_CTX_new");

	return nil
}

func (client *WebrtcConnection) LoadCertificates() error {
	/* set the local certificate from CertFile */

	pem_ptr := C.CString(PEM_FILE_PATH)

    if C.SSL_CTX_use_certificate_file(client.ssl_ctx,
		pem_ptr, C.SSL_FILETYPE_PEM) <= 0 {
		return errors.New("Error with SSL_CTX_use_certificate_file")
    }

	fmt.Println("Success with SSL_CTX_use_certificate");

	/* set the private key from KeyFile (may be the same as CertFile) */
    if C.SSL_CTX_use_PrivateKey_file(client.ssl_ctx,
		pem_ptr, C.SSL_FILETYPE_PEM) <= 0 {
		return errors.New("Error with SSL_CTX_use_PrivateKey_file")
    }

	fmt.Println("Success with SSL_CTX_use_PrivateKey");

	C.free(unsafe.Pointer(pem_ptr))

    /* verify private key */
    if C.SSL_CTX_check_private_key(client.ssl_ctx) == 0 {
		return errors.New("Private key does not match the public certificate")
	}

	return nil
}

func (client *WebrtcConnection) SetCipherList() error {

	/* SSL_CTX_set_cipher_list() sets the list of available ciphers
	  (TLSv1.2 and below) for ctx using the control string str. */

	/* SRTP is the Secure Real-Time Transport Protocol.
	  OpenSSL implements support for the "use_srtp" DTLS extension
	  defined in RFC5764. SSL_CTX_set_tlsext_use_srtp() to set its
	  use for all SSL objects subsequently created from an SSL_CTX.*/

	ciphers := GenericCiphers()

	ciphers_ptr := C.CString(ciphers)
	ciphers_list_ptr := C.CString("ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH")

	C.SSL_CTX_set_cipher_list(client.ssl_ctx, ciphers_list_ptr)
	if C.SSL_CTX_set_tlsext_use_srtp(client.ssl_ctx, ciphers_ptr) > 0 {
		return errors.New("Error in SSL_CTX_set_tlsext_use_srtp")
	}

	C.free(unsafe.Pointer(ciphers_list_ptr))
	C.free(unsafe.Pointer(ciphers_ptr))

	fmt.Println("Success with SSL_CTX_set_tlsext_use_srtp")

	return nil
}

func (client *WebrtcConnection) SSL_CTX_set_read_ahead(choice int) {

	/* SSL_CTX_set_read_ahead set whether we should read as many input bytes
	  as possible (for non-blocking reads) or not. */

	//Same: C.SSL_CTX_set_read_ahead(client.ssl_ctx, choice)
	C.SSL_CTX_ctrl(client.ssl_ctx, C.SSL_CTRL_SET_READ_AHEAD,
		C.long(choice), nil)

	fmt.Println("Success with SSL_CTX_set_read_ahead");
}

func (client *WebrtcConnection) SSL_new() error {
	/* SSL_new() creates a new SSL structure which is needed to hold the
	   data for a TLS/SSL connection. The new structure inherits the
	   settings of the underlying context ctx: connection method, options,
	   verification settings, timeout settings. */

	client.ssl = C.SSL_new(client.ssl_ctx)
	if client.ssl == nil {
		return errors.New("Error in SSL_new")
	}

	fmt.Println("Success with SSL_new");

	return nil
}

func (client *WebrtcConnection) CreateBIOs() error {
	/* A memory BIO is a source/sink BIO which uses memory
	   for its I/O. Data written to a memory BIO is stored
	   in a BUF_MEM structure which is extended as appropriate
	   to accommodate the stored data.*/

	client.r_bio = C.BIO_new(C.BIO_s_mem())
	client.w_bio = C.BIO_new(C.BIO_s_mem())
	if client.r_bio == nil || client.w_bio == nil {
		return errors.New("Error in BIO_new")
	}

	fmt.Println("BIO_new")

	return nil
}

func (client *WebrtcConnection) SSL_set_bio() error {
	/*SSL_set_bio() connects the BIOs rbio and wbio
	  for the read and write operations of the TLS/SSL
	  (encrypted) side of ssl.*/

	C.SSL_set_bio(client.ssl, client.r_bio, client.w_bio)
	fmt.Println("Success with SSL_set_bio")

	return nil
}

func (client *WebrtcConnection) SSL_set_mode() {

	/* SSL_set_mode() adds the mode set via bitmask in mode
	  to ssl. Options already set before are not cleared.*/

	/* SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
	   Make it possible to retry SSL_write() with changed
	  buffer location (the buffer contents must stay the same).
	  This is not the default to avoid the misconception that
	  non-blocking SSL_write() behaves like non-blocking write(). */

	/* SSL_MODE_ENABLE_PARTIAL_WRITE
	   Allow SSL_write(..., n) to return r with 0 < r < n
	   (i.e. report success when just a single record has been written).
	   When not set (the default), SSL_write() will only report success
	   once the complete chunk was written. Once SSL_write() returns with r,
	   r bytes have been successfully written and the next call to
	   SSL_write() must only send the n-r bytes left, imitating the
	   behaviour of write(). */

	mode := C.SSL_MODE_ENABLE_PARTIAL_WRITE |
		C.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER

	//Same: C.SSL_set_mode(client.ssl, mode)
	C.SSL_ctrl(client.ssl, C.SSL_CTRL_MODE, C.long(mode), nil)

	fmt.Println("Success with SSL_set_mode")
}

func (client *WebrtcConnection) SSL_set_options() error {
	/* An EC_KEY represents a public key and, optionally,
	   the associated private key. A new EC_KEY with no
	   associated curve can be constructed by calling
	   EC_KEY_new_ex() and specifying the associated
	   library context in ctx (see OSSL_LIB_CTX(3)) and
	   property query string propq. The ctx parameter may
	   be NULL in which case the default library context is
	   used. The reference count for the newly created EC_KEY
	   is initially set to 1. A curve can be associated with the
	   EC_KEY by calling EC_KEY_set_group(). */

	ecdh := C.EC_KEY_new_by_curve_name(C.NID_X9_62_prime256v1)
	if ecdh == nil {
		return errors.New("Error in EC_KEY_new_by_curve_name")
	}

	C.SSL_set_options(client.ssl, C.SSL_OP_SINGLE_ECDH_USE);
	//Same: C.SSL_set_tmp_ecdh(client.ssl, ecdh)
	C.SSL_ctrl(client.ssl, C.SSL_CTRL_SET_TMP_ECDH, 0, unsafe.Pointer(ecdh))
	C.EC_KEY_free(ecdh);

	fmt.Println("Success with SSL_set_options")

	return nil
}

func (client *WebrtcConnection) DtlsConnection() error {
	err := client.SSL_CTX_new()
	if err != nil {
		fmt.Println(err)

		return err
	}

	err = client.LoadCertificates()
	if err != nil {
		fmt.Println(err)

		return err
	}

	err = client.SetCipherList()
	if err != nil {
		fmt.Println(err)

		return err
	}

	client.SSL_CTX_set_read_ahead(YES)

	err = client.SSL_new()
	if err != nil {
		fmt.Println(err)

		return err
	}

	err = client.CreateBIOs()
	if err != nil {
		fmt.Println(err)

		return err
	}

	client.SSL_set_bio()

	client.SSL_set_mode()

	client.SSL_set_options()
	if err != nil {
		fmt.Println(err)

		return err
	}

	return nil
}

func (client *WebrtcConnection)try_connect() (int, error) {

	fmt.Println("Try_connect")

	ret := C.SSL_connect(client.ssl)
	code := C.SSL_get_error(client.ssl, ret)

	switch code {
	case C.SSL_ERROR_NONE:
		ret = 1
	case C.SSL_ERROR_WANT_READ:
	case C.SSL_ERROR_WANT_WRITE:
		ret = 0
	default:
		err := C.ERR_peek_last_error()
		fmt.Println("DTLS error: ", C.ERR_reason_error_string(err))
		return -1, errors.New("")
	}

	return int(ret), nil
}

func (client *WebrtcConnection) DtlsProccess() {
	fmt.Println("DTLS");
}
