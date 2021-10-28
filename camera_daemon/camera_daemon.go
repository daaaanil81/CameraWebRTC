package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net"
	"os"
	"time"
	"golang.org/x/net/websocket"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
)

var (
	DATABASE_PATH = "/etc/camera_server/static/database/database.txt"
	PUBLIC_MODE bool
)

func (client *WebrtcConnection) dtls() {

	certificate, err := util.LoadKeyAndCertificate(KEY_FILE_PATH, CRT_FILE_PATH)
	util.Check(err)

	rootCertificate, err := util.LoadCertificate(CRT_FILE_PATH)
	util.Check(err)
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	util.Check(err)
	certPool.AddCert(cert)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{*certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		RootCAs:              certPool,
		InsecureSkipVerify:   true,
	}

	fmt.Println("Opened certificate")

	// Connect to a DTLS server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dtlsConn, err := dtls.ClientWithContext(ctx, client.connectionUDP, config)
	fmt.Println("ClientWithcontext")
	util.Check(err)
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(dtlsConn)
}

func loadPage(filename string) ([]byte, error) {
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func formHandler(w http.ResponseWriter, r *http.Request) {
	var name, pass string

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}

	var file, err = os.OpenFile(DATABASE_PATH, os.O_RDWR, 0755)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer file.Close()

	fmt.Fscan(file, &name, &pass)

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username != name || password != pass {
		fmt.Fprintf(w, "Incorrect username or password entered\n")

		return
	}

	p, err := loadPage("/etc/camera_server/static/stream.html")
	if err != nil {
		fmt.Println(err.Error())

		return
	}

	w.Write(p)
}

func WSClient(ws *websocket.Conn) {
	var (
		conn WebrtcConnection
		answer string
		err error
	)

	done := make(chan bool, 1)

	command := "CON"
	flagICE := false
	flagSDP := false

	defer conn.CloseAll()

	SetupCloseHandler(&conn)

	fmt.Println("Connection...")

	err = conn.Init()
	if err != nil {
		return
	}

	err = conn.RequestStunServer()
	if err != nil {
		return
	}

	err = conn.ResponseStunServer()
	if err != nil {
		return
	}

	websocket.Message.Send(ws, command)

	for flagICE == false || flagSDP == false {
		websocket.Message.Receive(ws, &answer)
		switch answer {
		case "SDP": {
			conn.ReceiveSDP(ws)
			conn.SendSDP(ws)
			flagSDP = true
		}
		case "ICE": {
			conn.ReceiveICE(ws)
			conn.SendICE(ws)
			flagICE = true
		}
		case "ERROR":{
			websocket.Message.Receive(ws, &answer)
			fmt.Println(answer)
			return
		}

		default:
			fmt.Println("Command error")
		}

		fmt.Println("Wait...")
	}

	fmt.Println("Exchange finished")

	conn.connectionUDP.Close()

	laddr,_ := net.ResolveUDPAddr("udp",
		conn.ip_server+":"+conn.port_server)

	raddr,_ := net.ResolveUDPAddr("udp",
		conn.ip_client+":"+conn.port_client)

	conn.connectionUDP, err = net.DialUDP("udp", laddr, raddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	go conn.MessageController(done)
	<- done
	time.Sleep(3 * time.Second)
}

func main() {
	mode := os.Getenv("PUBLIC_MODE")
	if mode == "1" {
		PUBLIC_MODE = true
	} else {
		PUBLIC_MODE = false
	}

	fileServer := http.FileServer(http.Dir("/etc/camera_server/static"))
	http.Handle("/", fileServer)
	http.HandleFunc("/login", formHandler)
 	http.Handle("/ws", websocket.Handler(WSClient))

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServeTLS(":8080",
		CRT_FILE_PATH, KEY_FILE_PATH, nil); err != nil {
		log.Fatal(err)
	}
}
