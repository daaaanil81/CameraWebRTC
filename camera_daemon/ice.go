package main

import (
	"strings"
)

//candidate:3787395334 1 udp 2122260223 192.168.1.13 52653 typ host generation 0 ufrag 7NjZ network-id 1 network-cost 10

//candidate:397371602 1 udp 1686052607 109.86.197.114 52653 typ srflx raddr 192.168.1.13 rport 52653 generation 0 ufrag 7NjZ network-id 1 network-cost 10

var CANDIDATE = "candidate:"

var FOUNDATION_public = "397371602"

var FOUNDATION_local = "3787395334"

/* component-id is a positive integer between 1 and 256 (inclusive) that
   identifies the specific component of the data stream for which this is a
   candidate. It MUST start at 1 and MUST increment by 1 for each component of a
   particular candidate. */
var COMPONENT_ID = "1"

/* transport indicates the transport protocol for the candidate.
   This specification only defines UDP. */
var TRANSPORT = "udp"

/* priority is a positive integer between 1 and (2**31 - 1) inclusive.  */
var PRIORITY_local = "2122260223"
var PRIORITY_public = "1686052607"

/* cand-type encodes the type of candidate.
   This specification defines the values "host", "srflx", "prflx", and "relay"
   for host, server reflexive, peer reflexive, and relayed candidates, respectively. */
var CAND_TYPE = "typ host"

var GENERATION = "generation 0"

var UFRAG = "ufrag"

var NETWORK_ID = "network-id 1"

var NETWORK_COST = "network-cost 10"

func (client *WebrtcConnection) CreatePublicICE() string {

	ice := CANDIDATE + FOUNDATION_public + " " +
		COMPONENT_ID + " " +
		TRANSPORT + " " +
		PRIORITY_public + " " +
		client.ip_server + " " +
		client.port_server + " " +
		"typ srflx raddr " + client.ip_local + " rport " + client.port_local + " " +
		GENERATION + " " +
		UFRAG + " " + client.ice_ufrag_s + " " +
		NETWORK_ID + " " + NETWORK_COST

	return ice
}

func (client *WebrtcConnection) CreateLocalICE() string {

	ice := CANDIDATE + FOUNDATION_local + " " +
		COMPONENT_ID + " " +
		TRANSPORT + " " +
		PRIORITY_local + " " +
		client.ip_local + " " +
		client.port_local + " " +
		CAND_TYPE + " " +
		GENERATION + " " +
		UFRAG + " " + client.ice_ufrag_s + " " +
		NETWORK_ID + " " + NETWORK_COST

	return ice
}


func (client *WebrtcConnection) ParseICE(ice string) error {
	var err error

	arguments := strings.Split(ice, " ")

	if PUBLIC_MODE {
		client.ip_client = arguments[4]
	} else {
		client.ip_client = client.ip_local
	}

	client.port_client = arguments[5]
	client.ice_ufrag_c = arguments[15]

	return err
}
