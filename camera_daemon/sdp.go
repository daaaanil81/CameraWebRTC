package main

import (
	"strings"
)

var SDP_PATH = "/etc/camera_server/camera.sdp"

var ATTRIBUTE_V = "v=0"

var ATTRIBUTE_O = "o=- 0 0 IN IP4 127.0.0.1"

var ATTRIBUTE_S = "s=Live Stream"

var ATTRIBUTE_T = "t=0 0"

var ATTRIBUTE_M = "m=video"
var ATTRIBUTE_M_PAYLOAD_102 = "102"
var ATTRIBUTE_M_RTP_SAVP = "RTP/SAVP"

var ATTRIBUTE_C = "c=IN IP4"

var ATTRIBUTE_A_MID = "a=mid:0"
var ATTRIBUTE_A_TOOL = "a=tool"
var ATTRIBUTE_A_RTCP = "a=rtcp:"
var ATTRIBUTE_A_ICE_PWD = "a=ice-pwd:"
var ATTRIBUTE_A_ICE_UFRAG = "a=ice-ufrag:"
var ATTRIBUTE_A_RTCP_IP4 = "IN IP4"
var ATTRIBUTE_A_SENDONLY = "a=sendonly"
var ATTRIBUTE_A_RTCP_MUX = "a=rtcp-mux"
var ATTRIBUTE_A_SETUP_ACTIVE = "a=setup:active"
var ATTRIBUTE_A_ICE_OPTIONS = "a=ice-options:trickle"
var ATTRIBUTE_A_FINGERPRINT_SHA_256 = "a=fingerprint:sha-256"
var ATTRIBUTE_A_RTPMAP = "a=rtpmap:" + ATTRIBUTE_M_PAYLOAD_102 + " H264/90000"
var ATTRIBUTE_A_FMTP = "a=fmtp:" + ATTRIBUTE_M_PAYLOAD_102 +
	" packetization-mode=1"

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
	fingerprint, ice_ufrag, ice_pwd string) {

	line := ATTRIBUTE_A_RTCP + port + " " + ATTRIBUTE_A_RTCP_IP4 + " " + ip

	*sdpLines = append(*sdpLines, line)

	line = ATTRIBUTE_A_ICE_UFRAG + ice_ufrag
	*sdpLines = append(*sdpLines, line)

	line = ATTRIBUTE_A_ICE_PWD + ice_pwd
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

	append_attribute_M(&sdpLines, client.port_server)

	append_attribute_C(&sdpLines, client.ip_server)

	append_attribute_A(&sdpLines, client.ip_server, client.port_server,
		fingerprint, client.ice_ufrag_s, client.ice_pwd)

	sdp := strings.Join(sdpLines, "\r\n")

	sdp += "\r\n"

	return sdp
}
