package main

import (
	"fmt"
	"net"
	"strings"
	"crypto/x509"
	"math/rand"
	"time"
	"os"
	"os/signal"
	"syscall"
	"bytes"
	"encoding/hex"

	"golang.org/x/net/websocket"
)

var (
	IP_STUN_SERVER string = "108.177.15.127"
	PORT_STUN_SERVER string = "19302"
	last_port = 30000
	STUN_RESPONSE = []byte{0x01, 0x01}
	STUN_REQUEST = []byte{0x00, 0x01}
	RTP_MESSAGE = []byte{0x80, 0x00}
	BAD_RESULT = -1
	DEBUG_MODE = true
)

type WebrtcConnection struct {
	connectionUDP *net.UDPConn
	cert          *x509.Certificate
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

func (client *WebrtcConnection) OpenConnection() error {
	var err error = nil

	client.ip_local = GetOutboundIP()

	client.connectionUDP, err = net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
	})

	localAddr := client.connectionUDP.LocalAddr().String()
	index := strings.LastIndexByte(localAddr, ':')

	fmt.Println("Port Opened = ", localAddr)
	client.port_local = localAddr[index+1:]

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

	ice := client.CreateLocalICE()

	text := command + ice
	websocket.Message.Send(ws, text)

	if PUBLIC_MODE {
		ice = client.CreatePublicICE()

		text = command + ice
		websocket.Message.Send(ws, text)
	}

	return nil
}

func (client *WebrtcConnection) MessageController(done chan bool) {

	buffer := make([]byte, 256)

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
			if DEBUG_MODE {
				fmt.Println("Receive STUN Request\n")
				fmt.Printf("%s\n", hex.Dump(message))
			}

			err = client.SendResponse(message, browserAddr)
			if err != nil {
				fmt.Println(err)

				break
			}

			err = client.SendRequest()
			if err != nil {
				fmt.Println(err)

				break
			}

		} else if bytes.Equal(message[0:2], STUN_RESPONSE) {
			if DEBUG_MODE {
				fmt.Println("Receive STUN Response\n")
				fmt.Printf("%s\n", hex.Dump(message))
			}

			client.ReceiveResponse(message)
		} else if bytes.Equal(message[0:2], RTP_MESSAGE){
			if DEBUG_MODE {
				fmt.Println("Receive RTP\n")
				fmt.Printf("%s\n", hex.Dump(message))
			}

		} else {
			fmt.Println("This may be DTLS\n")
		}
	}

	done <- true
}

func (client *WebrtcConnection) CloseAll() {
	fmt.Println("Closing socket " + client.connectionUDP.LocalAddr().String())
	client.connectionUDP.Close()
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
