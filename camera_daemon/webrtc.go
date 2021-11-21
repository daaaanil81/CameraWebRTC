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
	"crypto/cipher"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/websocket"
)

var (
	IP_STUN_SERVER    string = "108.177.15.127"
	PORT_STUN_SERVER  string = "19302"
	STUN_RESPONSE            = []byte{0x01, 0x01}
	STUN_REQUEST             = []byte{0x00, 0x01}
	RTP_MESSAGE_1            = []byte{0x80, 0x60}
	RTP_MESSAGE_2            = []byte{0x80, 0xe0}
	RTCP_MESSAGE_1           = []byte{0x80, 0xc8}
	RTCP_MESSAGE_2           = []byte{0x81, 0xc9}
	BAD_RESULT               = -1
	DEBUG_MODE               = true
	PORT_FFMPEG              = 9011
	ffmpeg_mutex      sync.Mutex
	ffmpeg_connection *net.UDPConn
)

type CryptoKeys struct {
	ctx              *C.EVP_CIPHER_CTX
	have_session_key bool
	index            uint64
	master_key       [MASTER_KEY_LEN]byte
	master_salt      [MASTER_SALT_LEN]byte
	session_auth_key [SRTP_AUTH_KEY_LEN]byte
	session_key      [SESSION_KEY_LEN]byte
	session_salt     [SESSION_SALT_LEN]byte
	session_cipher   cipher.Block
	hash_sha         hash.Hash
}

type DtlsConnectionData struct {
	ssl_ctx     *C.SSL_CTX
	ssl         *C.SSL
	r_bio       *C.BIO
	w_bio       *C.BIO
	crypto_rtp  *CryptoKeys // Crypto RTP message for browser  \ SAME
	crypto_rtcp *CryptoKeys // Crypto RTCP message for browser / SAME
	decrypt     *CryptoKeys // Decrypto RTP and RTCP from browser
	//aes_evp     *C.EVP_CIPHER
}

type WebrtcConnection struct {
	connectionUDP *net.UDPConn
	cert          *x509.Certificate
	dtls_data     *DtlsConnectionData
	ip_server     string
	ip_local      string
	port_local    string
	port_server   string
	ip_client     string
	port_client   string
	ice_ufrag_s   string
	ice_ufrag_c   string
	ice_pwd_s     string
	ice_pwd_c     string
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func DEBUG_MESSAGE(str string) {
	if DEBUG_MODE {
		fmt.Println(str)
	}
}

func DEBUG_MESSAGE_BLOCK(str string, message []byte) {
	if DEBUG_MODE {
		fmt.Println(str)
		fmt.Printf("%s\n", hex.Dump(message))
	}
}

func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	index := strings.IndexByte(localAddr, ':')

	return localAddr[:index]
}

func RandStringRunes(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func CreateConnection() (*net.UDPConn, error) {
	connection, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: PORT_FFMPEG,
	})

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return connection, err
}

func StreamController(ip_address, port_str string) {

	var port int
	buffer := make([]byte, 0x10000)

	fmt.Sscan(port_str, &port)

	addr := &net.UDPAddr{
		IP:   net.ParseIP(ip_address),
		Port: port,
	}

	Lock := func() {
		ffmpeg_mutex.Lock()
		//		DEBUG_MESSAGE("Locked")
	}

	UnLock := func() {
		ffmpeg_mutex.Unlock()
		//		DEBUG_MESSAGE("Unlocked")
	}

	for {
		Lock()

		n, _, err := ffmpeg_connection.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println(err)
			break
		}

		if n == 0 {
			continue
		}

		//		DEBUG_MESSAGE_BLOCK("RTP Stream", buffer[:n])

		_, err = ffmpeg_connection.WriteToUDP(buffer[:n], addr)
		if err != nil {
			fmt.Println(err)
			break
		}

		UnLock()
	}

	defer DEBUG_MESSAGE("StreamController was finished, Port: " + port_str)
}

func (client *WebrtcConnection) OpenConnection() error {
	var err error = nil

	client.ip_local = GetOutboundIP()

	// if PUBLIC_MODE {
	// 	client.connectionUDP, err = net.ListenUDP("udp", nil,
	// 		&net.UDPAddr{
	// 			IP:   net.IPv4(224, 0, 0, 1),
	// 			Port: 0,
	// 		})
	// } else {
	client.connectionUDP, err = net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.ParseIP("0.0.0.0"),
	})
	// }

	if err != nil {
		fmt.Println(err)
		return err
	}

	localAddr := client.connectionUDP.LocalAddr().String()
	fmt.Println("Port Opened = ", localAddr)

	index := strings.LastIndexByte(localAddr, ':')
	if index != -1 {
		client.port_local = localAddr[index+1:]
	}

	//	client.connectionUDP.SetReadDeadline(time.Now().Add(time.Second * 5))

	return err
}

func (client *WebrtcConnection) Init() error {

	err := client.OpenConnection()
	if err != nil {
		return err
	}

	err = client.OpenCert()
	if err != nil {
		return err
	}

	client.ice_ufrag_s = RandStringRunes(4)
	client.ice_pwd_s = RandStringRunes(22)

	return nil
}

func (client *WebrtcConnection) ReceiveSDP(ws *websocket.Conn) error {
	var answer string

	websocket.Message.Receive(ws, &answer)

	client.parseSDP(answer)

	fmt.Printf("SDP: \n%s\n", answer)

	return nil
}

func (client *WebrtcConnection) SendSDP(ws *websocket.Conn) error {
	command := "SDP"

	fingerprint := FingerPrintCertificate(client.cert)

	sdp := client.CreateSDP(fingerprint)

	text := command + sdp
	websocket.Message.Send(ws, text)

	return nil
}

func (client *WebrtcConnection) ReceiveICE(ws *websocket.Conn) error {
	var answer string

	websocket.Message.Receive(ws, &answer)

	err := client.ParseICE(answer)
	if err != nil {
		fmt.Println(err)

		return err
	}

	fmt.Printf("ICE: \n%s\n", answer)

	return nil
}

func (client *WebrtcConnection) SendICE(ws *websocket.Conn) error {
	command := "ICE"
	var ice string

	if PUBLIC_MODE {
		ice = client.CreatePublicICE()
	} else {
		ice = client.CreateLocalICE()
	}

	text := command + ice
	websocket.Message.Send(ws, text)

	return nil
}

func (client *WebrtcConnection) MessageController(done chan bool) {

	buffer := make([]byte, 0x10000)
	dtls_flag := false
	var sequnce uint16 = 1

	for {
		n, browserAddr, err := client.connectionUDP.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println(err)

			break
		}

		message := buffer[:n]
		if DEBUG_MODE {
			fmt.Println("Receive INFO")
			fmt.Println("BrowserAddr: ", browserAddr.String())
		}

		if bytes.Equal(message[0:2], STUN_REQUEST) {

			DEBUG_MESSAGE_BLOCK("Receive STUN Request", message)

			err = client.SendResponse(message, browserAddr)
			if err != nil {
				fmt.Println(err)

				break
			}

			err = client.SendRequest(browserAddr)

		} else if bytes.Equal(message[0:2], STUN_RESPONSE) {
			DEBUG_MESSAGE_BLOCK("Receive STUN Response", message)

			err = client.ReceiveResponse(message)

			if dtls_flag == false {
				err = client.DtlsProccess(browserAddr, []byte{}, 0)
				dtls_flag = true
			}

		} else if bytes.Equal(message[0:2], RTP_MESSAGE_1) ||
			bytes.Equal(message[0:2], RTP_MESSAGE_2) {
			DEBUG_MESSAGE("Receive RTP")
			err = client.RtpToSrtp(message, &sequnce)

		} else if bytes.Equal(message[0:2], RTCP_MESSAGE_1) {
			DEBUG_MESSAGE("Receive RTCP")
			err = client.RtcpToSrtcp(message)

		} else if bytes.Equal(message[0:2], RTCP_MESSAGE_2) {
			DEBUG_MESSAGE("Receive RTCP from browser")
			//err = client.RtcpToSrtcp(message)

		} else {
			DEBUG_MESSAGE_BLOCK("Receive DTLS package", message)

			err = client.DtlsProccess(browserAddr, message, n)
		}

		if err != nil {
			fmt.Println(err)
			break
		}
	}

	done <- true
}

func (client *WebrtcConnection) CloseAll() {
	if client.connectionUDP != nil {
		fmt.Println("Closing socket " + client.connectionUDP.LocalAddr().String())

		client.connectionUDP.Close()
	}

	dtls_data := client.dtls_data

	if dtls_data.r_bio != nil {
		C.BIO_free(dtls_data.r_bio)
		fmt.Println("r_bio was cleaned")
	}

	if dtls_data.w_bio != nil {
		C.BIO_free(dtls_data.w_bio)
		fmt.Println("w_bio was cleaned")
	}

	// if dtls_data.ssl != nil {
	// 	C.SSL_free(dtls_data.ssl)
	// 	fmt.Println("ssl was cleaned")
	// }

	if dtls_data.ssl_ctx != nil {
		C.SSL_CTX_free(dtls_data.ssl_ctx)
		fmt.Println("ssl_ctx was cleaned")
	}
}

func SetupCloseHandler(client *WebrtcConnection) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		client.CloseAll()
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		os.Exit(0)
	}()
}
