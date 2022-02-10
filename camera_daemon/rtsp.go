package main

import (
	"fmt"
	"net"
	"strings"
)

var (
	STOP             = false
	client_rtp       = 9011
	client_rtcp      = 9012
	SERVER_PORT      = "server_port"
	SESSION          = "Session"
	OPTION_MESSAGE   = "OPTIONS rtsp://178.165.25.152:5587/axis-media/media.amp RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Danil\r\n\r\n"
	DESCRIBE_MESSAGE = "DESCRIBE rtsp://178.165.25.152:5587/axis-media/media.amp RTSP/1.0\r\nAccept: application/sdp\r\nCSeq: 2\r\nUser-Agent: Danil\r\n\r\n"
	SETUP_MESSAGE    = "SETUP rtsp://178.165.25.152:5587/axis-media/media.amp/trackID=1 RTSP/1.0\r\nTransport: RTP/AVP/UDP;unicast;client_port=10011-10012\r\nCSeq: 3\r\nUser-Agent: Danil\r\n\r\n"
	PLAY_MESSAGE_1   = "PLAY rtsp://178.165.25.152:5587/axis-media/media.amp RTSP/1.0\r\n"
	PLAY_MESSAGE_3   = "CSeq: 4\r\nUser-Agent: Danil\r\n"
	PLAY_MESSAGE_2   = "Range: npt=0.000-\r\n"

	TEARDOWN_MESSAGE_1 = "TEARDOWN rtsp://178.165.25.152:5587/axis-media/media.amp RTSP/1.0\r\n"
	TEARDOWN_MESSAGE_2 = "CSeq: 5\r\n"
	TEARDOWN_MESSAGE_4 = "User-Agent: Danil\r\n\r\n"
)

func PlayCommand(num_session string) string {
	PLAY_MESSAGE_4 := "Session: " + num_session + "\r\n\r\n"
	return PLAY_MESSAGE_1 + PLAY_MESSAGE_2 + PLAY_MESSAGE_3 + PLAY_MESSAGE_4
}

func TeardownCommand(num_session string) string {
	TEARDOWN_MESSAGE_3 := "Session: " + num_session + "\r\n"
	return TEARDOWN_MESSAGE_1 + TEARDOWN_MESSAGE_2 + TEARDOWN_MESSAGE_3 + TEARDOWN_MESSAGE_4
}

func SendMessage(conn *net.TCPConn, command string) (error, []byte) {
	var message [4095]byte
	fmt.Println(command)

	n, err := conn.Write([]byte(command))
	if err != nil {
		fmt.Println(err)
		return err, nil
	}

	n, err = conn.Read(message[:])
	if err != nil {
		fmt.Println(err)
		return err, nil
	}

	fmt.Printf("%s\n", message[:n])

	return nil, message[:n]
}

func ParsePort(message []byte) int {
	var port int

	start := strings.Index(string(message), SERVER_PORT)
	if start == -1 {
		fmt.Println("Message doesn't have ", SERVER_PORT)
		return start
	}

	start += len(SERVER_PORT) // 'server_port'
	start += 1                // '='

	end := strings.IndexByte(string(message[start:]), '-')
	if end == -1 {
		fmt.Println("Message doesn't have ", '-')
		return end
	}

	port_str := message[start : start+end]

	fmt.Sscanf(string(port_str), "%d", &port)

	return port
}

func ParseSession(message []byte) string {
	start := strings.Index(string(message), SESSION)
	if start == -1 {
		fmt.Println("Message doesn't have ", SESSION)
		return ""
	}

	start += len(SESSION) // 'Session'
	start += 1            // ':'
	start += 1            // ' '

	end := strings.IndexByte(string(message[start:]), ';')
	if end == -1 {
		fmt.Println("Message doesn't have ", ';')
		return ""
	}

	session := string(message[start : start+end])

	return session
}

