package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net"
)

var (
	HEADER_TYPE                      = []byte{0x00, 0x01}
	MAGICK                           = []byte{0x21, 0x12, 0xA4, 0x42}
	HEADER_ATTRIBUTE_LENGTH   uint16 = 4
	XOR_MAPPED_ADDRESS_TYPE          = []byte{0x00, 0x20}
	XOR_MAPPED_ADDRESS_LENGTH        = []byte{0x00, 0x08}
	XOR_MAPPED_ADDRESS_IP4           = []byte{0x00, 0x01}
	MESSAGE_INTEGRITY_TYPE           = []byte{0x00, 0x08}
	MESSAGE_INTEGRITY_LENGTH         = []byte{0x00, 0x14}
	FINGERPRINT_TYPE                 = []byte{0x80, 0x28}
	FINGERPRINT_LENGTH               = []byte{0x00, 0x04}
	FINGERPRINT               uint32 = 0x5354554e
	USERNAME_TYPE                    = []byte{0x00, 0x06}
	USERNAME_LENGTH                  = []byte{0x00, 0x09}
	PADDING                   uint16 = 3
	ICE_CONTROLLED_TYPE              = []byte{0x80, 0x29}
	ICE_CONTROLLED_LENGTH            = []byte{0x00, 0x08}
	PRIORITY_TYPE                    = []byte{0x00, 0x24}
	PRIORITY_LENGTH                  = []byte{0x00, 0x04}
	PRIORITY_VALUE            uint32 = 1845501695
	SOFTWARE_TYPE                    = []byte{0x80, 0x22}
	SOFTWARE_VALUE                   = "webrtpstream-1.0.0"
)

func CreateHeader(transaction []byte) []byte {
	var (
		request []byte
		header  []byte
	)

	header = append(header, HEADER_TYPE...)

	if len(transaction) == 0 {
		transaction = make([]byte, 12)
		rand.Read(transaction)
	} else {
		header[0] = 0x01
	}

	request = append(request, header...)
	request = append(request, 0, 0)
	request = append(request, MAGICK...)
	request = append(request, transaction...)

	return request
}

func XorMappedAddressDecode(buf []byte, index uint16, ip, port *string) uint16 {
	family := uint8(buf[index+1])
	*ip = fmt.Sprintf("%d.%d.%d.%d", buf[index+4]^MAGICK[0], buf[index+5]^MAGICK[1],
		buf[index+6]^MAGICK[2], buf[index+7]^MAGICK[3])
	*port = fmt.Sprintf("%d", int(buf[index+2]^MAGICK[0])<<8|
		int(buf[index+3]^MAGICK[1]))

	if DEBUG_MODE {
		fmt.Printf("Family %#x\n", family)
		fmt.Printf("IP: %s\n", *ip)
		fmt.Printf("Port: %s\n", *port)
	}

	return index + binary.LittleEndian.Uint16(XOR_MAPPED_ADDRESS_LENGTH)
}

func (client *WebrtcConnection) RequestStunServer() error {
	var (
		err         error
		request     []byte
		server      *net.UDPAddr
		transaction []byte
	)

	server, err = net.ResolveUDPAddr("udp",
		IP_STUN_SERVER+":"+PORT_STUN_SERVER)
	if err != nil {
		fmt.Println(err)

		return err
	}

	request = CreateHeader(transaction)

	DEBUG_MESSAGE_BLOCK("STUN request to Google", request)

	_, err = client.connectionUDP.WriteToUDP(request, server)
	if err != nil {
		fmt.Println(err)

		return err
	}

	return nil
}

func (client *WebrtcConnection) ResponseStunServer() error {

	var index uint16 = 20

	buffer := make([]byte, 256)

	n, _, err := client.connectionUDP.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println(err)

		return err
	}

	for index < uint16(n) {
		type_attr := []byte{buffer[index], buffer[index+1]}

		if bytes.Equal(type_attr, XOR_MAPPED_ADDRESS_TYPE) {
			index = XorMappedAddressDecode(buffer, index+HEADER_ATTRIBUTE_LENGTH,
				&client.ip_server, &client.port_server)
		}
	}

	DEBUG_MESSAGE_BLOCK("STUN response from Google", buffer[:n])

	return nil
}

func ParseRequestStun(stunRequest []byte) []byte {
	transaction := stunRequest[8:20]

	return transaction
}

func stun_xor_mapped(addr net.UDPAddr, body []byte) []byte {
	var response []byte

	ip := make([]byte, 4)
	port := make([]byte, 2)
	var RealIP []byte

	binary.BigEndian.PutUint16(port, uint16(addr.Port))

	DEBUG_MESSAGE_BLOCK("IP address:", addr.IP)

	if PUBLIC_MODE {
		RealIP = addr.IP[12:]
	} else {
		RealIP = addr.IP
	}

	for i := 0; i < 4; i++ {
		ip[i] = RealIP[i] ^ MAGICK[i]
	}

	for i := 0; i < 2; i++ {
		port[i] = port[i] ^ MAGICK[i]
	}

	response = append(response, XOR_MAPPED_ADDRESS_TYPE...)
	response = append(response, XOR_MAPPED_ADDRESS_LENGTH...)
	response = append(response, XOR_MAPPED_ADDRESS_IP4...)
	response = append(response, port...)
	response = append(response, ip...)

	length := binary.BigEndian.Uint16(body[2:4])
	length += binary.BigEndian.Uint16(XOR_MAPPED_ADDRESS_LENGTH)
	length += HEADER_ATTRIBUTE_LENGTH
	binary.BigEndian.PutUint16(body[2:4], length)

	body = append(body, response...)

	return body
}

func stun_message_integrity(body []byte, pwd string) []byte {
	var response []byte

	length := binary.BigEndian.Uint16(body[2:4])
	length += binary.BigEndian.Uint16(MESSAGE_INTEGRITY_LENGTH)
	length += HEADER_ATTRIBUTE_LENGTH
	binary.BigEndian.PutUint16(body[2:4], length)

	key := []byte(pwd)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(body))

	response = append(response, MESSAGE_INTEGRITY_TYPE...)
	response = append(response, MESSAGE_INTEGRITY_LENGTH...)
	response = append(response, h.Sum(nil)...)

	body = append(body, response...)

	return body
}

func stun_fingerprint(body []byte) []byte {
	var response []byte
	crc := make([]byte, 4)

	length := binary.BigEndian.Uint16(body[2:4])
	length += binary.BigEndian.Uint16(FINGERPRINT_LENGTH)
	length += HEADER_ATTRIBUTE_LENGTH
	binary.BigEndian.PutUint16(body[2:4], length)

	num := crc32.ChecksumIEEE(body) ^ FINGERPRINT
	binary.BigEndian.PutUint32(crc, num)

	response = append(response, FINGERPRINT_TYPE...)
	response = append(response, FINGERPRINT_LENGTH...)
	response = append(response, crc[:]...)

	body = append(body, response...)

	return body
}

func stun_username(ufrag_s, ufrag_c string, body []byte) []byte {
	var response []byte

	length := binary.BigEndian.Uint16(body[2:4])
	length += binary.BigEndian.Uint16(USERNAME_LENGTH)
	length += HEADER_ATTRIBUTE_LENGTH + PADDING
	binary.BigEndian.PutUint16(body[2:4], length)

	username := ufrag_c + ":" + ufrag_s

	fmt.Println("ufrag_c: ", ufrag_c)
	fmt.Println("ufrag_s: ", ufrag_s)

	response = append(response, USERNAME_TYPE...)
	response = append(response, USERNAME_LENGTH...)
	response = append(response, username...)
	response = append(response, 0, 0, 0)

	body = append(body, response...)

	return body
}

func stun_controlled(body []byte) []byte {
	var response []byte

	length := binary.BigEndian.Uint16(body[2:4])
	length += binary.BigEndian.Uint16(ICE_CONTROLLED_LENGTH)
	length += HEADER_ATTRIBUTE_LENGTH
	binary.BigEndian.PutUint16(body[2:4], length)

	data := make([]byte, ICE_CONTROLLED_LENGTH[1])
	rand.Read(data)

	response = append(response, ICE_CONTROLLED_TYPE...)
	response = append(response, ICE_CONTROLLED_LENGTH...)
	response = append(response, data...)

	body = append(body, response...)

	return body
}

func stun_priority(body []byte) []byte {
	var response []byte

	length := binary.BigEndian.Uint16(body[2:4])
	length += binary.BigEndian.Uint16(PRIORITY_LENGTH)
	length += HEADER_ATTRIBUTE_LENGTH
	binary.BigEndian.PutUint16(body[2:4], length)

	data := make([]byte, PRIORITY_LENGTH[1])
	binary.BigEndian.PutUint32(data, PRIORITY_VALUE)

	response = append(response, PRIORITY_TYPE...)
	response = append(response, PRIORITY_LENGTH...)
	response = append(response, data...)

	body = append(body, response...)

	return body
}

func stun_software(body []byte) []byte {
	len_b := make([]byte, 2)
	length_str := uint16(len(SOFTWARE_VALUE))

	var (
		response []byte
		i        uint16 = 0
		size     uint16 = (length_str + 3) & 0xfffc
	)

	length := binary.BigEndian.Uint16(body[2:4])
	length += size
	length += HEADER_ATTRIBUTE_LENGTH
	binary.BigEndian.PutUint16(body[2:4], length)
	binary.BigEndian.PutUint16(len_b, size)

	response = append(response, SOFTWARE_TYPE...)
	response = append(response, len_b...)
	response = append(response, SOFTWARE_VALUE...)

	for ; i < size-length_str; i++ {
		response = append(response, 0)
	}

	body = append(body, response...)

	return body
}

func check_message_integrity(body []byte, pwd string) {
	size := len(body) - 8 - 4 - 20
	var message []byte = make([]byte, size)

	copy(message, body[:size])

	length := binary.BigEndian.Uint16(message[2:4])
	length -= binary.BigEndian.Uint16(FINGERPRINT_LENGTH)
	length -= HEADER_ATTRIBUTE_LENGTH
	binary.BigEndian.PutUint16(message[2:4], length)

	key := []byte(pwd)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(message))

	//	fmt.Printf("%s\n", hex.Dump(h.Sum(nil)))
}

func check_fingerprint(buffer []byte) bool {
	fmt.Println("Check START Fingerprint")
	crc := make([]byte, 4)

	fmt.Printf("%s\n", hex.Dump(buffer[:len(buffer)-8]))

	body := buffer[:len(buffer)-8]

	num := crc32.ChecksumIEEE(body) ^ FINGERPRINT
	binary.BigEndian.PutUint32(crc, num)

	fmt.Printf("CRC_TEST: \n%s\n", hex.Dump(crc))

	fmt.Println("Check FINISH")
	return true
}

func (client *WebrtcConnection) SendRequest(browserAddr *net.UDPAddr) error {
	var (
		transaction []byte
		request     []byte
		err         error
	)

	//browserAddr, err := net.ResolveUDPAddr("udp",
	//	client.ip_client+":"+client.port_client)
	//if err != nil {
	//	fmt.Println(err)

	//	return err
	//}

	request = CreateHeader(transaction)
	request = stun_software(request)
	request = stun_username(client.ice_ufrag_s, client.ice_ufrag_c, request)
	request = stun_controlled(request)
	request = stun_priority(request)
	request = stun_message_integrity(request, client.ice_pwd_c)
	request = stun_fingerprint(request)

	DEBUG_MESSAGE_BLOCK("Create STUN Request", request)

	_, err = client.connectionUDP.WriteToUDP(request, browserAddr)
	if err != nil {
		fmt.Println(err)

		return err
	}

	return err
}

func (client *WebrtcConnection) ReceiveResponse(buffer []byte) error {
	var (
		index uint16 = 20
		ip    string
		port  string
	)

	type_attr := []byte{buffer[index], buffer[index+1]}

	if bytes.Equal(type_attr, XOR_MAPPED_ADDRESS_TYPE) {
		index = XorMappedAddressDecode(buffer, index+HEADER_ATTRIBUTE_LENGTH,
			&ip, &port)
	}

	if DEBUG_MODE {
		fmt.Printf("Address from response: %s:%s\n", ip, port)
	}

	return nil
}

func (client *WebrtcConnection) SendResponse(buffer []byte,
	browserAddr *net.UDPAddr) error {

	var (
		response    []byte
		transaction []byte
	)

	check_message_integrity(buffer, client.ice_pwd_s)

	transaction = ParseRequestStun(buffer)
	response = CreateHeader(transaction)
	response = stun_xor_mapped(*browserAddr, response)
	response = stun_message_integrity(response, client.ice_pwd_s)
	response = stun_fingerprint(response)

	DEBUG_MESSAGE_BLOCK("Create STUN Response", response)

	_, err := client.connectionUDP.WriteToUDP(response, browserAddr)
	if err != nil {
		fmt.Println(err)
	}

	return err
}
