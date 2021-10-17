package main

import (
	"strings"
	"fmt"
	"errors"
)

var SDP_PATH = "/etc/camera_server/camera.sdp"

var ATTRIBUTE_V = "v=0"

var ATTRIBUTE_O = "o=- 0 0 IN IP4 127.0.0.1"

var ATTRIBUTE_S = "s=Live Stream"

var ATTRIBUTE_T = "t=0 0"

var (
	ATTRIBUTE_M = "m=video"
	ATTRIBUTE_M_PAYLOAD_102 = "102"
	ATTRIBUTE_M_RTP_SAVP = "RTP/SAVP"
)

var ATTRIBUTE_C = "c=IN IP4"

var (
	ATTRIBUTE_A_MID = "a=mid:0"
	ATTRIBUTE_A_TOOL = "a=tool"
	ATTRIBUTE_A_RTCP = "a=rtcp:"
	ATTRIBUTE_A_ICE_PWD = "a=ice-pwd:"
	ATTRIBUTE_A_ICE_UFRAG = "a=ice-ufrag:"
	ATTRIBUTE_A_RTCP_IP4 = "IN IP4"
	ATTRIBUTE_A_SENDONLY = "a=sendonly"
	ATTRIBUTE_A_RTCP_MUX = "a=rtcp-mux"
	ATTRIBUTE_A_SETUP_ACTIVE = "a=setup:active"
	ATTRIBUTE_A_ICE_OPTIONS = "a=ice-options:trickle"
	ATTRIBUTE_A_FINGERPRINT_SHA_256 = "a=fingerprint:sha-256"
	ATTRIBUTE_A_RTPMAP = "a=rtpmap:" + ATTRIBUTE_M_PAYLOAD_102 + " H264/90000"
	ATTRIBUTE_A_FMTP = "a=fmtp:" + ATTRIBUTE_M_PAYLOAD_102 +
		" packetization-mode=1"
)

var END_LINE = "\r\n"

func append_attribute_V(sdpLines *[]string) {
	*sdpLines = append(*sdpLines, ATTRIBUTE_V)
}

func append_attribute_O(sdpLines *[]string) {
	*sdpLines = append(*sdpLines, ATTRIBUTE_O)
}

func append_attribute_S(sdpLines *[]string) {
	*sdpLines = append(*sdpLines, ATTRIBUTE_S)
}

func append_attribute_T(sdpLines *[]string) {
	*sdpLines = append(*sdpLines, ATTRIBUTE_T)
}

func append_attribute_M(sdpLines *[]string, port string) {
	line := ATTRIBUTE_M + " " + port + " " +
		ATTRIBUTE_M_RTP_SAVP + " " + ATTRIBUTE_M_PAYLOAD_102

	*sdpLines = append(*sdpLines, line)
}

func append_attribute_C(sdpLines *[]string, ip string) {
	line := ATTRIBUTE_C + " " + ip
	*sdpLines = append(*sdpLines, line)
}

func append_attribute_A(sdpLines *[]string, ip, port,
	fingerprint, ice_ufrag, ice_pwd_s string) {

	line := ATTRIBUTE_A_RTCP + port + " " + ATTRIBUTE_A_RTCP_IP4 + " " + ip

	*sdpLines = append(*sdpLines, line)

	line = ATTRIBUTE_A_ICE_UFRAG + ice_ufrag
	*sdpLines = append(*sdpLines, line)

	line = ATTRIBUTE_A_ICE_PWD + ice_pwd_s
	*sdpLines = append(*sdpLines, line)

	*sdpLines = append(*sdpLines, ATTRIBUTE_A_ICE_OPTIONS)
	*sdpLines = append(*sdpLines,
		ATTRIBUTE_A_FINGERPRINT_SHA_256 + " " + fingerprint)
	*sdpLines = append(*sdpLines, ATTRIBUTE_A_SETUP_ACTIVE)
	*sdpLines = append(*sdpLines, ATTRIBUTE_A_MID)
	*sdpLines = append(*sdpLines, ATTRIBUTE_A_SENDONLY)
	*sdpLines = append(*sdpLines, ATTRIBUTE_A_RTCP_MUX)
	*sdpLines = append(*sdpLines, ATTRIBUTE_A_RTPMAP)
	*sdpLines = append(*sdpLines, ATTRIBUTE_A_FMTP)
}

func (client *WebrtcConnection) CreateSDP(fingerprint string) string {

	var sdpLines []string = nil

	append_attribute_V(&sdpLines)

	append_attribute_O(&sdpLines)

	append_attribute_S(&sdpLines)

	append_attribute_T(&sdpLines)

	if PUBLIC_MODE {
		append_attribute_M(&sdpLines, client.port_server)

		append_attribute_C(&sdpLines, client.ip_server)

		append_attribute_A(&sdpLines, client.ip_server, client.port_server,
			fingerprint, client.ice_ufrag_s, client.ice_pwd_s)

	} else {
		append_attribute_M(&sdpLines, client.port_local)

		append_attribute_C(&sdpLines, client.ip_local)

		append_attribute_A(&sdpLines, client.ip_local, client.port_local,
			fingerprint, client.ice_ufrag_s, client.ice_pwd_s)
	}

	sdp := strings.Join(sdpLines, END_LINE)

	sdp += END_LINE

	return sdp
}

func (client *WebrtcConnection) parseSDP(client_sdp string) error {
	start := strings.Index(client_sdp, ATTRIBUTE_A_ICE_PWD)
	if start == -1 {
		fmt.Println("Don't found '" + ATTRIBUTE_A_ICE_PWD + "'")

		return errors.New("Don't found '" + ATTRIBUTE_A_ICE_PWD + "'")
	}

	end := strings.Index(client_sdp[start:], END_LINE)
	if end == -1 {
		fmt.Println("Don't found '" + END_LINE + "'")

		return errors.New("Don't found '" + END_LINE + "'")
	}

	client.ice_pwd_c = client_sdp[start+len(ATTRIBUTE_A_ICE_PWD):start+end]

	fmt.Println("ICE_PWD of client: ", client.ice_pwd_c)

	return nil
}
