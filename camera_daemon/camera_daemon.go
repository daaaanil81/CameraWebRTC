package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/websocket"
)

var (
	DATABASE_PATH = "/etc/camera_server/static/database/database.txt"
	PUBLIC_MODE   bool
)

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
		conn   WebrtcConnection
		answer string
		err    error
	)

	conn.dtls_data = new(DtlsConnectionData)
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
		case "SDP":
			{
				conn.ReceiveSDP(ws)
				conn.SendSDP(ws)
				flagSDP = true
			}
		case "ICE":
			{
				conn.ReceiveICE(ws)
				conn.SendICE(ws)
				flagICE = true
			}
		case "ERROR":
			{
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

	laddr, _ := net.ResolveUDPAddr("udp",
		conn.ip_server+":"+conn.port_server)

	fmt.Println("Laddr: ", conn.ip_server, ":", conn.port_server)

	raddr, _ := net.ResolveUDPAddr("udp",
		conn.ip_client+":"+conn.port_client)

	fmt.Println("Raddr: ", conn.ip_client, ":", conn.port_client)

	conn.connectionUDP, err = net.DialUDP("udp", laddr, raddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	// cmd := exec.Command("cvlc", "-vvv", "v4l2:///dev/video0:width=640:height=480:fps=30", "--sout-x264-preset", "ultrafast", "--sout-x264-tune", "film ", "--sout-transcode-threads", "8", "--no-sout-x264-interlaced", "--sout-x264-keyint", "-1", "--sout-x264-lookahead", "100", "--no-audio", "--sout-x264-vbv-maxrate", "6000", "--sout-x264-weightb", "--sout-x264-weightp=0", "--sout-x264-vbv-bufsize", "6000", "--sout", "'#transcode{vcodec=h264,vb=2000}:rtp{dst=127.0.0.1,port=10011,sdp=file:///home/user/test.sdp}'")

	// err = cmd.Run()
	// if err != nil {
	// 	log.Fatal("Error", err)
	// 	return
	// }

	go conn.MessageController(done)
	<-done
	time.Sleep(3 * time.Second)
}

func main() {
	var err error

	mode := os.Getenv("PUBLIC_MODE")
	if mode == "1" {
		fmt.Println("Enable PUBLIC_MODE")
		PUBLIC_MODE = true
	} else {
		fmt.Println("Disable PUBLIC_MODE")
		PUBLIC_MODE = false
	}

	fileServer := http.FileServer(http.Dir("/etc/camera_server/static"))
	http.Handle("/", fileServer)
	http.HandleFunc("/login", formHandler)
	http.Handle("/ws", websocket.Handler(WSClient))

	ffmpeg_connection_rtp, err = CreateConnection(PORT_RTP)
	if err != nil {
		return
	}

	CloseFfmpegRTP := func() {
		ffmpeg_mutex_rtp.Lock()
		ffmpeg_connection_rtp.Close()
		ffmpeg_mutex_rtp.Unlock()
	}

	defer CloseFfmpegRTP()

	ffmpeg_connection_rtcp, err = CreateConnection(PORT_RTCP)
	if err != nil {
		return
	}

	CloseFfmpegRTCP := func() {
		ffmpeg_mutex_rtcp.Lock()
		ffmpeg_connection_rtcp.Close()
		ffmpeg_mutex_rtcp.Unlock()
	}

	defer CloseFfmpegRTCP()

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServeTLS(":8080",
		CRT_FILE_PATH, KEY_FILE_PATH, nil); err != nil {
		log.Fatal(err)
	}
}
