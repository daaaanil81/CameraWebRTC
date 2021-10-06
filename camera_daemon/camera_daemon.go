package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/websocket"
)

var DATABASE_PATH = "/etc/camera_server/static/database/database.txt"

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
	var conn WebrtcConnection
	var answer string
	var err error

	command := "CON"
	flagICE := false
	flagSDP := false

	defer conn.CloseAll()

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

//	conn.SendReceiveStunClient()
	conn.ReceiveSendStunClient()
}

func main() {

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
