package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

var (
	RTP_HEADER_LEN         = 12
	RTCP_HEADER_LEN        = 8
	RTP_SSRC        uint32 = 534740855
	//RTP_SPS         = []byte{0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9, 0x40, 0xa0, 0x3d, 0xb0, 0x16, 0xa0, 0x20, 0x20, 0xa8, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x03, 0x01, 0xe4, 0x78, 0xb1, 0x6c, 0xb0}
	//RTP_SPS = []byte{0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x01, 0x6a, 0x02, 0x02, 0x0a, 0x80, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00, 0x00, 0x1e, 0x47, 0x8b, 0x16, 0xcb}
	//RTP_SPS = []byte{0x67, 0x64, 0x00, 0x0d, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x01, 0x6a, 0x02, 0x02, 0x0a, 0x80, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00, 0x00, 0x1e, 0x47, 0x8a, 0x14, 0xcb}
	//RTP_SPS = []byte{0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9, 0x80, 0xd8, 0x3d, 0xb0, 0x16, 0xa0, 0x20, 0x20, 0xa8, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x03, 0x01, 0x84, 0x78, 0xb1, 0x6c, 0xd0}
	//RTP_SPS = []byte{0x67, 0x64, 0x00, 0x14, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x01, 0x6a, 0x02, 0x02, 0x0a, 0x80, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00, 0x00, 0x1e, 0x47, 0x8a, 0x14, 0xcb}
	//RTP_SPS = []byte{0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9, 0x80, 0xa0, 0x3d, 0xb0, 0x16, 0xa0, 0x20, 0x20, 0xa8, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x03, 0x01, 0xe4, 0x78, 0xb1, 0x6c, 0xd0}
	//Local PC: RTP_SPS = []byte{0x67, 0x42, 0xc0, 0x1e, 0xda, 0x02, 0x80, 0xf6, 0xc0, 0x5a, 0x80, 0x80, 0x82, 0xa0, 0x00, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x07, 0x91, 0xe2, 0xc5, 0xd4}
	RTP_SPS = []byte{0x67, 0x42, 0xc0, 0x1e, 0xda, 0x02, 0x80, 0xf6, 0xc0, 0x5a, 0x80, 0x80, 0x81, 0x20, 0x00, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x07, 0x91, 0xe2, 0xc5, 0xd4}

	//RTP_PPS = []byte{0x68, 0xeb, 0xec, 0xb2, 0x2c}
	//RTP_PPS = []byte{0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0}
	//RTP_PPS = []byte{0x68, 0xe9, 0x7b, 0x3c, 0x8f}
	//RTP_PPS = []byte{0x68, 0xe9, 0x73, 0x3c, 0x8f}
	//RTP_PPS = []byte{0x68, 0xe9, 0x63, 0x3c, 0x8f}
	//RTP_PPS = []byte{0x68, 0xe9, 0x6b, 0x3c, 0x8f}
	//Local PC: RTP_PPS = []byte{0x68, 0xce, 0x37, 0x20}
	RTP_PPS = []byte{0x68, 0xce, 0x3c, 0x80}
)

func (keys *CryptoKeys) HmacShaRtcp(src []byte) ([]byte, error) {
	keys.hash_sha.Reset()

	_, err := keys.hash_sha.Write(src)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return keys.hash_sha.Sum(nil)[0:SRTP_AUTH_TAG], nil
}

func (keys *CryptoKeys) HmacShaRtp(src []byte, index uint64) ([]byte, error) {
	roc_buf := make([]byte, 4)
	roc := uint32((keys.index & 0xffffffff0000) >> 16)
	binary.BigEndian.PutUint32(roc_buf, roc)

	keys.hash_sha.Reset()

	_, err := keys.hash_sha.Write(src)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	_, err = keys.hash_sha.Write(roc_buf[:])
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return keys.hash_sha.Sum(nil)[0:SRTP_AUTH_TAG], nil
}

func (keys *CryptoKeys) AesCtr(iv, src, dst []byte) {
	stream := cipher.NewCTR(keys.session_cipher, iv)
	stream.XORKeyStream(dst, src)
}

func (keys *CryptoKeys) GenerateIV(ssrc uint32, index uint64) []byte {
	var iv [MASTER_KEY_LEN]byte

	index <<= 16

	idxh := uint32((index & 0xffffffff00000000) >> 32)
	idxl := uint32(index & 0xffffffff)

	DEBUG_MESSAGE_BLOCK("IV BEFORE", iv[:])

	//fmt.Printf("ssrc = %08x\n", ssrc)
	//fmt.Printf("idxh = %08x\n", idxh)
	//fmt.Printf("idxl = %08x\n", idxl)

	binary.BigEndian.PutUint32(iv[4:8], ssrc)
	binary.BigEndian.PutUint32(iv[8:12], idxh)
	binary.BigEndian.PutUint32(iv[12:], idxl)

	for i := range keys.session_salt {
		iv[i] ^= keys.session_salt[i]
	}

	DEBUG_MESSAGE_BLOCK("IV AFTER", iv[:])

	return iv[:]
}

func (keys *CryptoKeys) GenerateRtcpIV(ssrc uint32, index uint64) []byte {
	var iv [MASTER_KEY_LEN]byte

	idxh := uint32(index >> 16)
	idxl := uint32(index & 0xffff)

	DEBUG_MESSAGE_BLOCK("IV BEFORE", iv[:])

	fmt.Printf("ssrc = %08x\n", ssrc)
	fmt.Printf("idxh = %08x\n", idxh)
	fmt.Printf("idxl = %08x\n", idxl)

	binary.BigEndian.PutUint32(iv[4:8], ssrc)
	binary.BigEndian.PutUint32(iv[8:12], idxh)
	binary.BigEndian.PutUint32(iv[12:], idxl)

	for i := range keys.session_salt {
		iv[i] ^= keys.session_salt[i]
	}

	DEBUG_MESSAGE_BLOCK("IV AFTER", iv[:])

	return iv[:]
}

func PacketIndex(seq_num uint16, srtp_index uint64) uint64 {
	seq := seq_num
	if srtp_index == 0 {
		srtp_index = uint64(seq)
	}

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	var s_l uint16 = uint16(srtp_index & 0x00000000ffff)
	var roc uint32 = uint32(srtp_index & 0xffffffff0000 >> 16)
	var v uint32 = 0

	if s_l < 0x8000 {
		if (seq-s_l) > 0x8000 && roc > 0 {
			v = (roc - 1) % 0x10000
		} else {
			v = roc
		}
	} else {
		if (s_l - 0x8000) > seq {
			v = (roc + 1) % 0x10000
		} else {
			v = roc
		}
	}

	srtp_index = (uint64((v << 16) | uint32(seq))) & 0xffffffffffff

	return srtp_index
}

func (keys *CryptoKeys) CryptoGenSessionKey(out []byte, label uint8) error {
	var src [MASTER_KEY_LEN]byte
	var i uint16 = 0

	l := len(out)
	len_message := ((l + MASTER_KEY_LEN) / MASTER_KEY_LEN) * MASTER_KEY_LEN

	dst := make([]byte, len_message)
	copy(src[:MASTER_SALT_LEN], keys.master_salt[:])

	src[7] ^= label

	DEBUG_MESSAGE_BLOCK("TEST X:", src[:])

	aes_block, err := aes.NewCipher(keys.master_key[:])
	if err != nil {
		fmt.Println(err)
		return err
	}

	for n := 0; n < l; n += MASTER_KEY_LEN {
		binary.BigEndian.PutUint16(src[MASTER_SALT_LEN:], i)
		aes_block.Encrypt(dst[n:n+MASTER_KEY_LEN], src[:])
		i += 1
	}

	copy(out, dst[:l])

	DEBUG_MESSAGE(fmt.Sprintf("Label: 0x%02X", label))
	DEBUG_MESSAGE_BLOCK("Generated session key: master key", keys.master_key[:])
	DEBUG_MESSAGE_BLOCK("Generated session key: master salt", keys.master_salt[:])

	switch label {
	case 0x00:
		DEBUG_MESSAGE_BLOCK("Generated RTP session key: ", out)
	case 0x01:
		DEBUG_MESSAGE_BLOCK("Generated RTP auth key: ", out)
	case 0x02:
		DEBUG_MESSAGE_BLOCK("Generated RTP session salt: ", out)
	case 0x03:
		DEBUG_MESSAGE_BLOCK("Generated RTCP session key: result", out)
	case 0x04:
		DEBUG_MESSAGE_BLOCK("Generated RTCP auth key: ", out)
	case 0x05:
		DEBUG_MESSAGE_BLOCK("Generated RTCP session salt: ", out)
	}

	return nil
}

func (dtls_data *DtlsConnectionData) CheckSessionKeysRtcp() error {

	crypto_rtcp := dtls_data.crypto_rtcp

	if crypto_rtcp.have_session_key == true {
		return nil
	}

	err := crypto_rtcp.CryptoGenSessionKey(crypto_rtcp.session_key[:], 0x03)
	if err != nil {
		return err
	}

	crypto_rtcp.session_cipher, err = aes.NewCipher(crypto_rtcp.session_key[:])
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = crypto_rtcp.CryptoGenSessionKey(crypto_rtcp.session_auth_key[:], 0x04)
	if err != nil {
		return err
	}

	err = crypto_rtcp.CryptoGenSessionKey(crypto_rtcp.session_salt[:], 0x05)
	if err != nil {
		return err
	}

	crypto_rtcp.hash_sha = hmac.New(sha1.New, crypto_rtcp.session_auth_key[:])
	crypto_rtcp.have_session_key = true

	return nil
}

func (dtls_data *DtlsConnectionData) CheckSessionKeysRtp() error {

	crypto_rtp := dtls_data.crypto_rtp

	if crypto_rtp.have_session_key == true {
		return nil
	}

	err := crypto_rtp.CryptoGenSessionKey(crypto_rtp.session_key[:], 0x00)
	if err != nil {
		return err
	}

	crypto_rtp.session_cipher, err = aes.NewCipher(crypto_rtp.session_key[:])
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = crypto_rtp.CryptoGenSessionKey(crypto_rtp.session_auth_key[:], 0x01)
	if err != nil {
		return err
	}

	err = crypto_rtp.CryptoGenSessionKey(crypto_rtp.session_salt[:], 0x02)
	if err != nil {
		return err
	}

	crypto_rtp.hash_sha = hmac.New(sha1.New, crypto_rtp.session_auth_key[:])
	crypto_rtp.have_session_key = true

	return nil
}

func RtcpPayload(buffer []byte) uint32 {
	v := (buffer[0] & 0xC0) >> 6
	p := (buffer[0] & 0x20) >> 5
	x := (buffer[0] & 0x10) >> 4
	cc := buffer[0] & 0x0F
	payload_type := buffer[1]
	length := binary.BigEndian.Uint16(buffer[2:4])
	ssrc := binary.BigEndian.Uint32(buffer[4:8])

	if DEBUG_MODE {
		fmt.Println("V = ", v)
		fmt.Println("P = ", p)
		fmt.Println("X = ", x)
		fmt.Println("CC = ", cc)
		fmt.Println("Length = ", length)
		/* 1 byte */
		fmt.Println("Payload type = ", payload_type)
		/* 2-3 bytes */
		fmt.Println("SSRC = ", ssrc)
	}

	return ssrc
}

func RtpIFrame(rtp []byte, sequence uint16) []byte {
	var nul_frame [1024]byte

	index := 0

	for i := 0; i < 2; i++ {
		nul_frame[index] = rtp[i]
		index += 1
	}

	nul_frame[index] = uint8(sequence >> 8)
	index += 1
	nul_frame[index] = uint8(sequence)
	index += 1

	for i := 0; i < 8; i++ {
		nul_frame[index] = rtp[i+4]
		index += 1
	}

	nul_frame[index] = 0x38
	index += 1
	nul_frame[index] = uint8(len(RTP_SPS) >> 8)
	index += 1
	nul_frame[index] = uint8(len(RTP_SPS))
	index += 1

	for i := 0; i < len(RTP_SPS); i++ {
		nul_frame[index] = RTP_SPS[i]
		index += 1
	}

	nul_frame[index] = uint8(len(RTP_PPS) >> 8)
	index += 1
	nul_frame[index] = uint8(len(RTP_PPS))
	index += 1

	for i := 0; i < len(RTP_PPS); i++ {
		nul_frame[index] = RTP_PPS[i]
		index += 1
	}

	DEBUG_MESSAGE_BLOCK("TEST SPS: ", nul_frame[:index])

	return nul_frame[:index]
}

func RtpPayload(buffer []byte, sequence *uint16) (uint32, []byte, uint16) {
	var nul_frame []byte
	var seq_num_frame uint16 = 0
	fmt.Println("Sequence: ", binary.BigEndian.Uint16(buffer[2:4]))
	buffer[1] = (buffer[1] & 0x80) | 102 /** Change payload in rtp header */
	v := (buffer[0] & 0xC0) >> 6
	p := (buffer[0] & 0x20) >> 5
	x := (buffer[0] & 0x10) >> 4
	cc := buffer[0] & 0x0F
	m := (buffer[1] & 0x80) >> 7
	payload_type := buffer[1] & 0x7F
	timestamp := binary.BigEndian.Uint32(buffer[4:8])
	ssrc := binary.BigEndian.Uint32(buffer[8:12])
	indicator_type := buffer[12] & 0x1F
	header_type := buffer[13] & 0x1F
	header_start := (buffer[13] & 0x80) >> 7

	if indicator_type == 28 && header_type == 5 && header_start == 1 {
		nul_frame = RtpIFrame(buffer, *sequence)
		seq_num_frame = *sequence
		*sequence += 1

		*sequence = uint16(*sequence)
	}

	buffer[2] = byte((*sequence & 0xFF00) >> 8)
	buffer[3] = byte(*sequence & 0xFF)

	seq_num := binary.BigEndian.Uint16(buffer[2:4])

	if DEBUG_MODE {
		fmt.Println("V = ", v)
		fmt.Println("P = ", p)
		fmt.Println("X = ", x)
		fmt.Println("CC = ", cc)
		/* 1 byte */
		fmt.Println("M = ", m)
		fmt.Println("Payload type = ", payload_type)
		/* 2-3 bytes */
		fmt.Println("Sequence number = ", seq_num)
		/* 4-7 bytes */
		fmt.Println("Timestamp = ", timestamp)
		/* 8-11 bytes */
		fmt.Println("SSRC = ", ssrc)

		fmt.Println("Indicator_type = ", indicator_type)
		fmt.Println("Header_type = ", header_type)
		fmt.Println("Package_start = ", header_start)
	}

	fmt.Println("SSRC = ", ssrc)
	return ssrc, nul_frame, seq_num_frame
}

func (client *WebrtcConnection) RtcpToSrtcp(buffer []byte) error {
	var hash_sha []byte

	dtls_data := client.dtls_data
	crypto_rtcp := dtls_data.crypto_rtcp
	payload := buffer[RTCP_HEADER_LEN:]
	len_buffer := len(buffer)
	crypto_buffer := make([]byte, len_buffer)

	err := dtls_data.CheckSessionKeysRtcp()
	if err != nil {
		fmt.Println(err)
		return err
	}

	ssrc := RtcpPayload(buffer)

	copy(crypto_buffer[:RTCP_HEADER_LEN], buffer[:RTCP_HEADER_LEN])

	iv := crypto_rtcp.GenerateRtcpIV(ssrc, crypto_rtcp.index)

	DEBUG_MESSAGE_BLOCK("All message before: ", buffer)

	crypto_rtcp.AesCtr(iv[:], payload, crypto_buffer[RTCP_HEADER_LEN:])

	fmt.Println("Simple RTCP")

	crypto_buffer = append(crypto_buffer, make([]byte, 4)...)
	binary.BigEndian.PutUint32(crypto_buffer[len(crypto_buffer)-4:], uint32(crypto_rtcp.index))
	crypto_buffer[len(crypto_buffer)-4] |= 0x80

	hash_sha, err = crypto_rtcp.HmacShaRtcp(crypto_buffer)
	if err != nil {
		fmt.Println(err)
		return err
	}

	crypto_buffer = append(crypto_buffer, hash_sha...)

	DEBUG_MESSAGE_BLOCK("All message after: ", crypto_buffer)

	crypto_rtcp.index += 1

	err = client.WriteToBrowser(crypto_buffer)
	if err != nil {
		return err
	}

	return nil
}

func (client *WebrtcConnection) RtpFail(buffer []byte, sequence uint16) error {
	var hash_sha []byte

	dtls_data := client.dtls_data
	crypto_rtp := dtls_data.crypto_rtp
	payload := buffer[RTP_HEADER_LEN:]
	len_buffer := len(buffer)
	crypto_buffer := make([]byte, len_buffer+SRTP_AUTH_TAG)

	err := dtls_data.CheckSessionKeysRtp()
	if err != nil {
		fmt.Println(err)
		return err
	}

	buffer[1] = (buffer[1] & 0x80) | 102 // Change payload in rtp header
	buffer[2] = byte((sequence & 0xFF00) >> 8)
	buffer[3] = byte(sequence & 0xFF)                  // Don't change sequence
	binary.BigEndian.PutUint32(buffer[8:12], RTP_SSRC) // Change ssrc for fake RTP packate

	copy(crypto_buffer[:RTP_HEADER_LEN], buffer[:RTP_HEADER_LEN])

	index := PacketIndex(sequence, crypto_rtp.index) // Don't change index for future packages

	iv := crypto_rtp.GenerateIV(RTP_SSRC, index)

	fmt.Println("Fail RTP")

	DEBUG_MESSAGE_BLOCK("All message before: ", buffer)

	crypto_rtp.AesCtr(iv[:], payload, crypto_buffer[RTP_HEADER_LEN:])

	hash_sha, err = crypto_rtp.HmacShaRtp(crypto_buffer[:len_buffer], index)
	if err != nil {
		fmt.Println(err)
		return err
	}

	copy(crypto_buffer[len_buffer:], hash_sha)

	DEBUG_MESSAGE_BLOCK("All message after: ", crypto_buffer)

	err = client.WriteToBrowser(crypto_buffer)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func (client *WebrtcConnection) RtpToSrtp(buffer []byte, sequence *uint16) error {
	var hash_sha []byte

	dtls_data := client.dtls_data
	crypto_rtp := dtls_data.crypto_rtp
	payload := buffer[RTP_HEADER_LEN:]
	len_buffer := len(buffer)
	crypto_buffer := make([]byte, len_buffer+SRTP_AUTH_TAG)

	err := dtls_data.CheckSessionKeysRtp()
	if err != nil {
		fmt.Println(err)
		return err
	}

	ssrc, nul_frame, seq_num := RtpPayload(buffer, sequence)
	len_frame := len(nul_frame)

	if len_frame != 0 {
		crypto_frame := make([]byte, len_frame+SRTP_AUTH_TAG)
		copy(crypto_frame[:RTP_HEADER_LEN], nul_frame[:RTP_HEADER_LEN])
		crypto_rtp.index = PacketIndex(seq_num, crypto_rtp.index)

		iv := crypto_rtp.GenerateIV(ssrc, crypto_rtp.index)

		fmt.Println("SPS/PPS")

		DEBUG_MESSAGE_BLOCK("All message SPS before: ", nul_frame)

		crypto_rtp.AesCtr(iv[:], nul_frame[RTP_HEADER_LEN:], crypto_frame[RTP_HEADER_LEN:])

		hash_sha, err = crypto_rtp.HmacShaRtp(crypto_frame[:len_frame], crypto_rtp.index)
		if err != nil {
			fmt.Println(err)
			return err
		}

		copy(crypto_frame[len_frame:], hash_sha)

		DEBUG_MESSAGE_BLOCK("All message after: ", crypto_frame)

		err = client.WriteToBrowser(crypto_frame)
		if err != nil {
			fmt.Println(err)
			return err
		}
	}

	copy(crypto_buffer[:RTP_HEADER_LEN], buffer[:RTP_HEADER_LEN])

	crypto_rtp.index = PacketIndex(*sequence, crypto_rtp.index)

	iv := crypto_rtp.GenerateIV(ssrc, crypto_rtp.index)

	fmt.Println("Simple RTP")

	DEBUG_MESSAGE_BLOCK("All message before: ", buffer)

	crypto_rtp.AesCtr(iv[:], payload, crypto_buffer[RTP_HEADER_LEN:])

	hash_sha, err = crypto_rtp.HmacShaRtp(crypto_buffer[:len_buffer], crypto_rtp.index)
	if err != nil {
		fmt.Println(err)
		return err
	}

	copy(crypto_buffer[len_buffer:], hash_sha)

	DEBUG_MESSAGE_BLOCK("All message after: ", crypto_buffer)

	*sequence += 1

	*sequence = uint16(*sequence)

	err = client.WriteToBrowser(crypto_buffer)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}
