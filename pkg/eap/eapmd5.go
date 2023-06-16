package eap

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"

	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

func (e *EAPMessage) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, e.Code)
	binary.Write(buf, binary.BigEndian, e.Identifier)
	binary.Write(buf, binary.BigEndian, e.Length)

	if e.Type != 0 {
		binary.Write(buf, binary.BigEndian, e.Type)
	}

	if len(e.Value) != 0 {
		buf.Write(e.Value)
	}

	return buf.Bytes()
}

func (e *EAPMessage) GenerateEAPChellenge() []byte {
	var chellenge = make([]byte, 16)
	rand.Read(chellenge)

	return chellenge
}

// https://datatracker.ietf.org/doc/html/rfc2869#section-5.14
func GenerateMessageAuthenticator(packet *radius.Packet) {
	packet.Add(rfc2869.MessageAuthenticator_Type, make([]byte, 16))

	// Create a new HMAC-MD5 hasher
	h := hmac.New(md5.New, packet.Secret)

	// Write the RADIUS message into the hasher
	calc, _ := packet.MarshalBinary()
	h.Write(calc)

	// Calculate HMAC-MD5 digest
	digest := h.Sum(nil)

	packet.Set(rfc2869.MessageAuthenticator_Type, digest)
}

func VerifyMessageAuthenticator(packet radius.Packet) bool {
	messageAuthenticator := packet.Get(rfc2869.MessageAuthenticator_Type)
	packet.Set(rfc2869.MessageAuthenticator_Type, make([]byte, 16))

	// Create a new HMAC-MD5 hasher
	h := hmac.New(md5.New, packet.Secret)

	// Write the RADIUS message into the hasher
	verify, _ := packet.Encode()
	h.Write(verify)

	// Calculate HMAC-MD5 digest
	check := h.Sum(nil)

	packet.Set(rfc2869.MessageAuthenticator_Type, messageAuthenticator)
	return hmac.Equal(messageAuthenticator, check)
}

func VerifyMD5Chellenge(eapRequest EAPMessage, password string, vm5c []byte) bool {
	h := md5.New()
	h.Write([]byte{eapRequest.Identifier})
	h.Write([]byte(password))
	h.Write(vm5c)
	expectedMD5Value := h.Sum(nil)

	return bytes.Equal(expectedMD5Value, eapRequest.Value[1:17])
}
