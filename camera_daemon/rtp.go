package main

/*
#cgo LDFLAGS: -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

*/
import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
)

var (
	RTP_HEADER_LEN  = 12
	RTCP_HEADER_LEN = 8
)

//func PacketIndex(seq_num uint16, srtp_index uint64) uint64 {
//	seq := seq_num
//	if srtp_index == 0 {
//		srtp_index = uint64(seq)
//	}

//	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
//	var s_l uint16 = uint16(srtp_index & 0x00000000ffff)
//	var roc uint32 = uint32(srtp_index & 0xffffffff0000 >> 16)
//	var v uint32 = 0

//	if s_l < 0x8000 {
//		if (seq-s_l) > 0x8000 && roc > 0 {
//			v = (roc - 1) % 0x10000
//		} else {
//			v = roc
//		}
//	} else {
//		if (s_l - 0x8000) > seq {
//			v = (roc + 1) % 0x10000
//		} else {
//			v = roc
//		}
//	}

//	srtp_index = (uint64(v<<16) | uint64(seq)) & 0xffffffffffff

//	return srtp_index
//}

//func (keys *CryptoKeys) AesCmSessionKeyInit(aes_evp *C.EVP_CIPHER) {

//	keys.session_key_ctx = C.EVP_CIPHER_CTX_new()
//	C.EVP_EncryptInit_ex(keys.session_key_ctx, aes_evp, nil,
//		(*C.uchar)(&keys.session_key[0]), nil)
//}

//func AesCtr(out, in, iv []byte, ctx *C.EVP_CIPHER_CTX) error {
//	var (
//		key_block [16]byte
//		length    int = len(out)
//		counter   int = 0
//		l         int
//	)

//	DEBUG_MESSAGE(fmt.Sprintf("Length of Key: %d", length))

//	for length != 0 {
//		outlen := C.int(len(key_block))
//		C.EVP_EncryptUpdate(ctx, (*C.uchar)(&key_block[0]), &outlen,
//			(*C.uchar)(&iv[0]), C.int(len(iv)))
//		if outlen != 16 {
//			return errors.New("EVP_EncryptUpdate return < 16 bytes")
//		}

//		DEBUG_MESSAGE_BLOCK("Key_block:", key_block[:])
//		DEBUG_MESSAGE_BLOCK("IV:", iv)

//		if length > 16 {
//			l = 16
//		} else {
//			l = length
//		}

//		length -= l

//		for i := 0; i < l; i += 1 {
//			out[i+counter*16] = in[i+counter*16] ^ key_block[i]
//		}

//		for i := 15; i >= 0; i -= 1 {
//			iv[i] += 1
//			if iv[i] != 0 {
//				break
//			}
//		}

//		counter += 1
//	}

//	return nil
//}

//func AesCtrNoCtx(out, in, key, iv []byte, aes_evp *C.EVP_CIPHER) error {

//	var (
//		ctx   *C.EVP_CIPHER_CTX
//		block [16]byte
//		len   int
//	)

//	outlen := C.int(len)

//	ctx = C.EVP_CIPHER_CTX_new()

//	C.EVP_EncryptInit_ex(ctx, aes_evp, nil, (*C.uchar)(&key[0]), nil)
//	err := AesCtr(out, in, iv, ctx)

//	if err != nil {
//		return err
//	}

//	C.EVP_EncryptFinal_ex(ctx, (*C.uchar)(&block[0]), &outlen)

//	C.EVP_CIPHER_CTX_free(ctx)

//	return nil
//}

//func prf_n(out, key, x []byte, aes_evp *C.EVP_CIPHER) error {
//	var iv [16]byte
//	var in [32]byte

//	copy(iv[:], x[:])
//	// iv[14] =s iv[15] = 0;   := x << 16
//	return AesCtrNoCtx(out, in[:], key, iv[:], aes_evp)
//}

//func (keys *CryptoKeys) CryptoGenSessionKey(aes_evp *C.EVP_CIPHER,
//	label uint8, index_len int, out []byte) error {

//	var x [14]byte
//	var key_id [7]byte /* [ label, 48-bit ROC || SEQ ] */

//	end := MASTER_SALT_LEN - 1
//	/* key_id[1..6] := r; or 1..4 for rtcp
//	 * key_derivation_rate == 0 --> r == 0 */

//	key_id[0] = label

//	copy(x[:], keys.master_salt[:])

//	for i := end - index_len; i < MASTER_SALT_LEN; i++ {
//		x[i] = key_id[i-(end-index_len)] ^ x[i]
//	}

//	DEBUG_MESSAGE_BLOCK("TEST X:", x[:])

//	err := prf_n(out, keys.master_key[:], x[:], aes_evp)

//	DEBUG_MESSAGE(fmt.Sprintf("Label: 0x%02X", label))
//	DEBUG_MESSAGE_BLOCK("Generated session key: master key", keys.master_key[:])
//	DEBUG_MESSAGE_BLOCK("Generated session key: master salt", keys.master_salt[:])
//	DEBUG_MESSAGE_BLOCK("Generated session key: result", out)

//	return err
//}

//func (dtls_data *DtlsConnectionData) CheckSessionKeysRtp() error {

//	crypto_rtp := dtls_data.crypto_rtp

//	if crypto_rtp.have_session_key == true {
//		return nil
//	}

//	err := crypto_rtp.CryptoGenSessionKey(dtls_data.aes_evp, 0x00,
//		6, crypto_rtp.session_key[:])
//	if err != nil {
//		return err
//	}

//	err = crypto_rtp.CryptoGenSessionKey(dtls_data.aes_evp, 0x01,
//		6, crypto_rtp.session_auth_key[:])
//	if err != nil {
//		return err
//	}

//	err = crypto_rtp.CryptoGenSessionKey(dtls_data.aes_evp, 0x02,
//		6, crypto_rtp.session_salt[:])
//	if err != nil {
//		return err
//	}

//	crypto_rtp.have_session_key = true
//	crypto_rtp.AesCmSessionKeyInit(dtls_data.aes_evp)

//	return nil
//}

//func (dtls_data *DtlsConnectionData) CheckSessionKeysRtcp() error {

//	crypto_rtcp := dtls_data.crypto_rtcp

//	if crypto_rtcp.have_session_key == true {
//		return nil
//	}

//	err := crypto_rtcp.CryptoGenSessionKey(dtls_data.aes_evp, 0x03,
//		6, crypto_rtcp.session_key[:])
//	if err != nil {
//		return err
//	}

//	err = crypto_rtcp.CryptoGenSessionKey(dtls_data.aes_evp, 0x04,
//		6, crypto_rtcp.session_auth_key[:])
//	if err != nil {
//		return err
//	}

//	err = crypto_rtcp.CryptoGenSessionKey(dtls_data.aes_evp, 0x05,
//		6, crypto_rtcp.session_salt[:])
//	if err != nil {
//		return err
//	}

//	crypto_rtcp.have_session_key = true
//	crypto_rtcp.AesCmSessionKeyInit(dtls_data.aes_evp)

//	return nil
//}

////static int hmac_sha1_rtp(struct crypto_context *c, unsigned char *payload, struct str_key *in, uint64_t index)
//func (keys *CryptoKeys) HmacShaRtp(in []byte, index uint64) []byte {
//	var hmac [20]byte
//	var hc *C.HMAC_CTX

//	roc_buf := make([]byte, 4)
//	roc := uint32((index & 0xffffffff0000) >> 16)
//	binary.BigEndian.PutUint32(roc_buf, roc)

//	hc = C.HMAC_CTX_new()

//	C.HMAC_Init_ex(hc, unsafe.Pointer(&keys.session_auth_key[0]), C.int(SRTP_AUTH_KEY_LEN), C.EVP_sha1(), nil)
//	C.HMAC_Update(hc, (*C.uchar)(&in[0]), C.ulong(len(in)))

//	C.HMAC_Update(hc, (*C.uchar)(&roc_buf[0]), 4)
//	C.HMAC_Final(hc, (*C.uchar)(&hmac[0]), nil)

//	C.HMAC_CTX_free(hc)

//	out := append(in, hmac[0:SRTP_AUTH_TAG]...)
//	return out
//}

//func (keys *CryptoKeys) CryptoEncryptRtp(payload, out []byte, ssrc uint32, index uint64) {
//	var iv [16]byte
//	var ivi [4]uint32
//	b := make([]byte, 4)

//	index <<= 16

//	idxh := uint32((index & 0xffffffff00000000) >> 32)
//	idxl := uint32(index & 0xffffffff)

//	copy(iv[:], keys.session_salt[:])
//	iv[14] = 0
//	iv[15] = 0

//	fmt.Printf("iv = % x\n", iv)

//	buf := new(bytes.Buffer)
//	binary.Write(buf, binary.LittleEndian, iv)

//	rbuf := bytes.NewReader(buf.Bytes())
//	binary.Read(rbuf, binary.LittleEndian, &ivi)

//	fmt.Printf("ivi[0] = %08x\n", ivi[0])
//	fmt.Printf("ivi[1] = %08x\n", ivi[1])
//	fmt.Printf("ivi[2] = %08x\n", ivi[2])
//	fmt.Printf("ivi[3] = %08x\n", ivi[3])

//	fmt.Println("===================================================================")

//	binary.LittleEndian.PutUint32(b, ssrc)
//	ivi[1] ^= binary.BigEndian.Uint32(b)

//	binary.LittleEndian.PutUint32(b, idxh)
//	ivi[2] ^= binary.BigEndian.Uint32(b)

//	binary.LittleEndian.PutUint32(b, idxl)
//	ivi[3] ^= binary.BigEndian.Uint32(b)

//	buf = new(bytes.Buffer)
//	binary.Write(buf, binary.LittleEndian, ivi)

//	rbuf = bytes.NewReader(buf.Bytes())
//	binary.Read(rbuf, binary.LittleEndian, &iv)

//	fmt.Printf("ivi[0] = %08x\n", ivi[0])
//	fmt.Printf("ivi[1] = %08x\n", ivi[1])
//	fmt.Printf("ivi[2] = %08x\n", ivi[2])
//	fmt.Printf("ivi[3] = %08x\n", ivi[3])

//	fmt.Printf("iv = % x\n", iv)

//	AesCtr(out, payload, iv[:], keys.session_key_ctx)
//}

//// (unsigned char *rtp, unsigned char *sps, unsigned int sequnce, struct pthread_arguments *p_a)

////struct rtp_header *rtp, struct str_key *payload, uint16_t *sequnce_origin, uint16_t *sequnce_new,
////						 unsigned char *all_mess, struct str_key *rtp_sps, struct pthread_arguments *p_a, int l)
//func RtpPayload(buffer []byte, sequnce uint16, ssrc *uint32) error {

//	buffer[1] = (buffer[1] & 0x80) | 102 /** Change payload in rtp header */
//	buffer[2] = byte((sequnce & 0xFF00) >> 8)
//	buffer[3] = byte(sequnce & 0xFF)

//	v := (buffer[0] & 0xC0) >> 6
//	p := (buffer[0] & 0x20) >> 5
//	x := (buffer[0] & 0x10) >> 4
//	cc := buffer[0] & 0x0F
//	m := (buffer[1] & 0x80) >> 7
//	payload_type := buffer[1] & 0x7F
//	seq_num := binary.BigEndian.Uint16(buffer[2:4]) // 1054i // 1055 // 1056 // 1057i // 1058
//	timestamp := binary.BigEndian.Uint32(buffer[4:8])
//	*ssrc = binary.BigEndian.Uint32(buffer[8:12])
//	//sq_copy := *sequnce_new;
//	indicator_type := buffer[12] & 0x1F
//	header_type := buffer[13] & 0x1F
//	header_start := (buffer[13] & 0x80) >> 7

//	if DEBUG_MODE {
//		fmt.Println("V = ", v)
//		fmt.Println("P = ", p)
//		fmt.Println("X = ", x)
//		fmt.Println("CC = ", cc)
//		/* 1 byte */
//		fmt.Println("M = ", m)
//		fmt.Println("Payload type = ", payload_type)
//		/* 2-3 bytes */
//		fmt.Println("Sequence number = ", seq_num)
//		/* 4-7 bytes */
//		fmt.Println("Timestamp = ", timestamp)
//		/* 8-11 bytes */
//		fmt.Println("SSRC = ", *ssrc)

//		fmt.Println("Indicator_type = ", indicator_type)
//		fmt.Println("Header_type = ", header_type)
//		fmt.Println("Package_start = ", header_start)
//	}

//	return nil
//}

//func RtcpPayload(buffer []byte) uint32 {
//	v := (buffer[0] & 0xC0) >> 6
//	p := (buffer[0] & 0x20) >> 5
//	x := (buffer[0] & 0x10) >> 4
//	cc := buffer[0] & 0x0F
//	payload_type := buffer[1]
//	length := binary.BigEndian.Uint16(buffer[2:4])
//	ssrc := binary.BigEndian.Uint32(buffer[4:8])

//	if DEBUG_MODE {
//		fmt.Println("V = ", v)
//		fmt.Println("P = ", p)
//		fmt.Println("X = ", x)
//		fmt.Println("CC = ", cc)
//		fmt.Println("Length = ", length)
//		/* 1 byte */
//		fmt.Println("Payload type = ", payload_type)
//		/* 2-3 bytes */
//		fmt.Println("SSRC = ", ssrc)
//	}

//	return ssrc
//}

//func (keys *CryptoKeys) HmacSha1Rtcp(in []byte) []byte {

//	var hmac [20]byte

//	C.HMAC(C.EVP_sha1(), unsafe.Pointer(&keys.session_auth_key[0]), C.int(SRTP_AUTH_KEY_LEN), (*C.uchar)(&in[0]), C.ulong(len(in)), (*C.uchar)(&hmac[0]), nil)

//	out := append(in, hmac[0:SRTP_AUTH_TAG]...)
//	return out
//}

//func (client *WebrtcConnection) RtcpToSrtcp(buffer []byte) error {
//	//int rtcp_avp_to_savp(struct crypto_context *crypto_from_camera, unsigned char *rtcp, int* length, uint32_t* index_rtcp)

//	var port int = 0

//	dtls_data := client.dtls_data
//	crypto_rtcp := dtls_data.crypto_rtcp
//	payload := buffer[8:]

//	ssrc := RtcpPayload(buffer)

//	err := dtls_data.CheckSessionKeysRtcp()
//	if err != nil {
//		fmt.Println(err)
//		return err
//	}

//	crypto_rtcp.CryptoEncryptRtp(payload, payload, ssrc, crypto_rtcp.index)

//	index_buffer := make([]byte, 4)

//	binary.BigEndian.PutUint32(index_buffer, 0x80000000|uint32(crypto_rtcp.index))

//	buffer = append(buffer, index_buffer...)

//	crypto_buffer := crypto_rtcp.HmacSha1Rtcp(buffer)

//	//idx = (void *) to_auth.str + to_auth.len;
//	//*idx = htonl((0x80000000ULL | *index_rtcp));
//	//to_auth.len += sizeof(*idx);
//	//crypto_from_camera->params.crypto_suite->hash_rtcp(crypto_from_camera, to_auth.str + to_auth.len, &to_auth);

//	//to_auth.len += crypto_from_camera->params.crypto_suite->srtcp_auth_tag;
//	//*length = to_auth.len;
//	crypto_rtcp.index += 1

//	fmt.Sscan(client.port_client, &port)

//	browserAddr := &net.UDPAddr{
//		IP:   net.ParseIP(client.ip_local),
//		Port: port,
//	}

//	_, err = client.connectionUDP.WriteToUDP(crypto_buffer, browserAddr)
//	if err != nil {
//		return err
//	}
//	return nil
//}

//func (client *webrtcconnection) rtptosrtp(buffer []byte, sequnce *uint16) error {
//	var ssrc uint32 = 0
//	var port int = 0

//	dtls_data := client.dtls_data
//	crypto_rtp := dtls_data.crypto_rtp
//	payload := buffer[12:]

//	err := rtppayload(buffer, *sequnce, &ssrc)
//	if err != nil {
//		fmt.println(err)
//		return err
//	}

//	err = dtls_data.checksessionkeysrtp()
//	if err != nil {
//		fmt.println(err)
//		return err
//	}

//	crypto_rtp.index = packetindex(*sequnce, crypto_rtp.index)

//	//debug_message_block("all message before: ", buffer)

//	//debug_message_block("payload before: ", payload)

//	crypto_rtp.cryptoencryptrtp(payload, payload, ssrc, crypto_rtp.index)

//	//debug_message_block("payload after cryptoencryptrtp: ", payload)

//	//func (keys *cryptokeys) hmacshartp(in, index uint64) {
//	crypto_buffer := crypto_rtp.hmacshartp(buffer, crypto_rtp.index)

//	debug_message_block("all message after: ", crypto_buffer)

//	// crypto_encrypt_rtp(&p_a->crypto, &payload, rtp_h.ssrc, index);
//	// /** function hash all mess and add
//	//  * payload->str + payload->len --- place where will save 10 bytes
//	//  * mes_all --- all message
//	// */
//	// crypto_hash_rtp(&p_a->crypto, (unsigned char *)(mes_all.str + mes_all.len), &mes_all, index);
//	// payload.len += p_a->crypto.params.crypto_suite->srtp_auth_tag;
//	// mes_all.len += p_a->crypto.params.crypto_suite->srtp_auth_tag;
//	// p_a->sequnce_new += 1;
//	// if(p_a->sequnce_new == 0)
//	// 	printf("error ------ error sequnce = 0\n");
//	// *l = mes_all.len;

//	*sequnce += 1

//	fmt.sscan(client.port_client, &port)

//	browseraddr := &net.udpaddr{
//		ip:   net.parseip(client.ip_local),
//		port: port,
//	}

//	_, err = client.connectionudp.writetoudp(crypto_buffer, browseraddr)
//	if err != nil {
//		return err
//	}

//	return nil
//}

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

func RtpPayload(buffer []byte, sequnce uint16) uint32 {

	buffer[1] = (buffer[1] & 0x80) | 102 /** Change payload in rtp header */
	buffer[2] = byte((sequnce & 0xFF00) >> 8)
	buffer[3] = byte(sequnce & 0xFF)

	v := (buffer[0] & 0xC0) >> 6
	p := (buffer[0] & 0x20) >> 5
	x := (buffer[0] & 0x10) >> 4
	cc := buffer[0] & 0x0F
	m := (buffer[1] & 0x80) >> 7
	payload_type := buffer[1] & 0x7F
	seq_num := binary.BigEndian.Uint16(buffer[2:4]) // 1054i // 1055 // 1056 // 1057i // 1058
	timestamp := binary.BigEndian.Uint32(buffer[4:8])
	ssrc := binary.BigEndian.Uint32(buffer[8:12])
	indicator_type := buffer[12] & 0x1F
	header_type := buffer[13] & 0x1F
	header_start := (buffer[13] & 0x80) >> 7

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

	return ssrc
}

func (client *WebrtcConnection) RtcpToSrtcp(buffer []byte) error {
	var port int
	var hash_sha []byte

	dtls_data := client.dtls_data
	crypto_rtcp := dtls_data.crypto_rtcp
	payload := buffer[RTCP_HEADER_LEN:]
	len_buffer := len(buffer)
	crypto_buffer := make([]byte, len_buffer)

	ssrc := RtcpPayload(buffer)

	copy(crypto_buffer[:RTCP_HEADER_LEN], buffer[:RTCP_HEADER_LEN])

	err := dtls_data.CheckSessionKeysRtcp()
	if err != nil {
		fmt.Println(err)
		return err
	}

	iv := crypto_rtcp.GenerateRtcpIV(ssrc, crypto_rtcp.index)

	DEBUG_MESSAGE_BLOCK("All message before: ", buffer)

	crypto_rtcp.AesCtr(iv[:], payload, crypto_buffer[RTCP_HEADER_LEN:])

	fmt.Println("Length received buffer: ", len_buffer, " length crypto buffer: ", len(crypto_buffer))

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

	//crypto_rtcp.CryptoEncryptRtp(payload, payload, ssrc, crypto_rtcp.index)

	//index_buffer := make([]byte, 4)

	//binary.BigEndian.PutUint32(index_buffer, 0x80000000|uint32(crypto_rtcp.index))

	//buffer = append(buffer, index_buffer...)

	//crypto_buffer := crypto_rtcp.HmacSha1Rtcp(buffer)

	////idx = (void *) to_auth.str + to_auth.len;
	////*idx = htonl((0x80000000ULL | *index_rtcp));
	////to_auth.len += sizeof(*idx);
	////crypto_from_camera->params.crypto_suite->hash_rtcp(crypto_from_camera, to_auth.str + to_auth.len, &to_auth);

	////to_auth.len += crypto_from_camera->params.crypto_suite->srtcp_auth_tag;
	////*length = to_auth.len;
	crypto_rtcp.index += 1

	fmt.Sscan(client.port_client, &port)

	browserAddr := &net.UDPAddr{
		IP:   net.ParseIP(client.ip_local),
		Port: port,
	}

	_, err = client.connectionUDP.WriteToUDP(crypto_buffer, browserAddr)
	if err != nil {
		return err
	}

	return nil
}

func (client *WebrtcConnection) RtpToSrtp(buffer []byte, sequnce *uint16) error {
	var port int
	var hash_sha []byte

	dtls_data := client.dtls_data
	crypto_rtp := dtls_data.crypto_rtp
	payload := buffer[RTP_HEADER_LEN:]
	len_buffer := len(buffer)
	crypto_buffer := make([]byte, len_buffer+SRTP_AUTH_TAG)

	ssrc := RtpPayload(buffer, *sequnce)

	copy(crypto_buffer[:RTP_HEADER_LEN], buffer[:RTP_HEADER_LEN])

	err := dtls_data.CheckSessionKeysRtp()
	if err != nil {
		fmt.Println(err)
		return err
	}

	crypto_rtp.index = PacketIndex(*sequnce, crypto_rtp.index)

	iv := crypto_rtp.GenerateIV(ssrc, crypto_rtp.index)

	fmt.Println("Len buffer: ", len_buffer)

	DEBUG_MESSAGE_BLOCK("All message before: ", buffer)

	crypto_rtp.AesCtr(iv[:], payload, crypto_buffer[RTP_HEADER_LEN:])

	hash_sha, err = crypto_rtp.HmacShaRtp(crypto_buffer[:len_buffer], crypto_rtp.index)
	if err != nil {
		fmt.Println(err)
		return err
	}

	copy(crypto_buffer[len_buffer:], hash_sha)

	DEBUG_MESSAGE_BLOCK("All message after: ", crypto_buffer)

	*sequnce += 1

	fmt.Sscan(client.port_client, &port)

	browseraddr := &net.UDPAddr{
		IP:   net.ParseIP(client.ip_local),
		Port: port,
	}

	_, err = client.connectionUDP.WriteToUDP(crypto_buffer, browseraddr)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}
