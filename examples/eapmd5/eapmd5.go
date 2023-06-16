package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"layeh.com/radius"
	"layeh.com/radius/pkg/eap"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

var vm5c = make(map[uint8][]byte, 100000)

const secret = "123456"

func main() {
	var users map[string]string = map[string]string{"cody": "whatever"}

	handler := func(w radius.ResponseWriter, r *radius.Request) {
		eapMessage := rfc2869.EAPMessage_Get(r.Packet)

		var eapRequest eap.EAPMessage
		var eapResponse eap.EAPMessage

		if !eap.VerifyMessageAuthenticator(*r.Packet) {
			fmt.Println("MessageAuthenticator is invalid")
			return
		}

		if eapMessage != nil {
			eapRequest.Code = eap.Code(eapMessage[0])
			eapRequest.Identifier = eapMessage[1]
			eapRequest.Length = binary.BigEndian.Uint16(eapMessage[2:4])
			eapRequest.Type = eap.Type(eapMessage[4])
			eapRequest.Value = eapMessage[5:eapRequest.Length]
		}

		if eapRequest.Code == eap.CODE_RESPONSE {

			switch eapRequest.Type {
			case eap.TYPE_IDENTITY:
				response := r.Response(radius.CodeAccessChallenge)
				hostname, _ := os.Hostname()

				eapResponse.Code = eap.CODE_REQUEST
				eapResponse.Identifier = eapRequest.Identifier
				eapResponse.Type = eap.TYPE_MD5_CHALLENGE

				chellenge := eapRequest.GenerateEAPChellenge()

				// Record EAP MD5 Chellenge for later verification
				vm5c[response.Identifier+1] = chellenge
				eapResponse.Length = uint16(5 + 1 + len(chellenge) + len(hostname))

				// EAP MD5 Chellenge Length + EAP MD5 Chellenge + EAP Extra (Server Hostname)
				eapResponse.Value = append([]byte{byte(len(chellenge))}, append(chellenge, []byte(hostname)...)...)

				response.Add(rfc2869.EAPMessage_Type, eapResponse.Encode())
				eap.GenerateMessageAuthenticator(response)

				w.Write(response)
			case eap.TYPE_MD5_CHALLENGE:
				response := r.Response(radius.CodeAccessAccept)
				username := r.Get(rfc2865.UserName_Type)

				if username == nil {
					response.Code = radius.CodeAccessReject
					eapResponse.Code = eap.CODE_FAILURE
					response.Add(rfc2865.ReplyMessage_Type, []byte("Request Denied"))
				} else {
					// Verify EAP MD5 Chellenge
					if eap.VerifyMD5Chellenge(eapRequest, users[string(username)], vm5c[response.Identifier]) {
						eapResponse.Code = eap.CODE_SUCCESS
					} else {
						response.Code = radius.CodeAccessReject
						eapResponse.Code = eap.CODE_FAILURE
						response.Add(rfc2865.ReplyMessage_Type, []byte("Request Denied"))
					}
				}

				eapResponse.Identifier = eapRequest.Identifier
				eapResponse.Length = 4

				response.Add(rfc2869.EAPMessage_Type, eapResponse.Encode())
				eap.GenerateMessageAuthenticator(response)

				w.Write(response)
			}

		}
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(secret)),
	}

	log.Printf("Starting server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
