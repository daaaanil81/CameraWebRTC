package main

import (
	"encoding/hex"
	"crypto/rand"
	"fmt"
	"net"
)

var HEADER_TYPE = []byte{0x00, 0x01}
var MAGICK = []byte{0x21, 0x12, 0xA4, 0x42}

var HEADER_ATTRIBUTE_LENGTH = 4
var XOR_MAPPED_ADDRESS_TYPE = []byte{0x00, 0x20}
var XOR_MAPPED_ADDRESS_LENGTH = 0x08

func CreateHeader() []byte {
	var request []byte
	transaction := make([]byte, 12)

	rand.Read(transaction)

	request = append(request, HEADER_TYPE...)
	request = append(request, 0, 0)
	request = append(request, MAGICK...)
	request = append(request, transaction...)

	return request
}

func XorMappedAddress(buf []byte, index int, ip, port *string) int {
	family := uint8(buf[index+1])
	*ip = fmt.Sprintf("%d.%d.%d.%d", buf[index+4]^MAGICK[0], buf[index+5]^MAGICK[1],
		buf[index+6]^MAGICK[2], buf[index+7]^MAGICK[3])
	*port = fmt.Sprintf("%d", int(buf[index+2]^MAGICK[0])<<8|
		int(buf[index+3]^MAGICK[1]))

	fmt.Printf("Family %#x\n", family)
	fmt.Printf("IP: %s\n", *ip)
	fmt.Printf("Port: %s\n", *port)

	return index + XOR_MAPPED_ADDRESS_LENGTH
}

func (client *WebrtcConnection) SendReceiveStunClient() error {

	browserAddr, err := net.ResolveUDPAddr("udp4",
		client.ip_client+":"+client.port_client)
	if err != nil {
		fmt.Println(err)

		return err
	}

	fmt.Println("Create Addr for browser.")

	request := CreateHeader()

	fmt.Printf("%s\n", hex.Dump(request))

	_, err = client.connectionUDP.WriteToUDP(request, browserAddr)
	if err != nil {
		fmt.Println(err)

		return err
	}

	return nil
}

func (client *WebrtcConnection) ReceiveSendStunClient() error {

	buffer := make([]byte, 256)

	_, err := client.connectionUDP.Read(buffer)
	if err != nil {
		fmt.Println(err)

		return err
	}

	//fmt.Println("Addr: ", addr.String())

	fmt.Printf("%s\n", hex.Dump(buffer))

	return nil
}
