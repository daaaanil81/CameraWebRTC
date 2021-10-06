package main

import (
	"strings"
)

var CANDIDATE = "candidate:"

var FOUNDATION_public = "1968211759"

var FOUNDATION_local = "2196157330"

/* component-id is a positive integer between 1 and 256 (inclusive) that
   identifies the specific component of the data stream for which this is a
   candidate. It MUST start at 1 and MUST increment by 1 for each component of a
   particular candidate. */
var COMPONENT_ID = "1"

/* transport indicates the transport protocol for the candidate.
   This specification only defines UDP. */
var TRANSPORT = "udp"

/* priority is a positive integer between 1 and (2**31 - 1) inclusive.  */
var PRIORITY_local = "2122252543"
var PRIORITY_public = "1677729535"

/* cand-type encodes the type of candidate.
   This specification defines the values "host", "srflx", "prflx", and "relay"
   for host, server reflexive, peer reflexive, and relayed candidates, respectively. */
var CAND_TYPE = "typ host"

var GENERATION = "generation 0"

var UFRAG = "ufrag"

var NETWORK_COST = "network-cost 999"

func (client *WebrtcConnection) CreatePublicICE() string {

	ice := CANDIDATE + FOUNDATION_public + " " +
		COMPONENT_ID + " " +
		TRANSPORT + " " +
		PRIORITY_public + " " +
		client.ip_server + " " +
		client.port_server + " " +
		"typ srflx raddr " + client.ip_local + " rport " + client.port_local + " " +
		UFRAG + " " + client.ice_ufrag_s + " " +
		NETWORK_COST + "\r\n"

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
		UFRAG + " " + client.ice_ufrag_s + " " +
		NETWORK_COST + "\r\n"

	return ice
}


func (client *WebrtcConnection) ParseICE(ice string) error {
	var err error

	arguments := strings.Split(ice, " ")

	client.ip_client = arguments[4]
	client.port_client = arguments[5]
	client.ice_uflag_c = arguments[15]

	return err
}
