package eap

type Code uint8

const (
	CODE_REQUEST  Code = 1
	CODE_RESPONSE Code = 2
	CODE_SUCCESS  Code = 3
	CODE_FAILURE  Code = 4
)

type Type uint8

const (
	TYPE_RESERVED      Type = 0
	TYPE_IDENTITY      Type = 1
	TYPE_NOTIFICATION  Type = 2
	TYPE_NAK           Type = 3
	TYPE_MD5_CHALLENGE Type = 4
	TYPE_OTP           Type = 5
	TYPE_TOKEN         Type = 6
	TYPE_TLS           Type = 13
	TYPE_SECURID       Type = 15
	TYPE_LEAP          Type = 17
	TYPE_SIM           Type = 18
	TYPE_TTLS          Type = 21
	TYPE_AKA           Type = 23
	TYPE_PEAP          Type = 25
	TYPE_MSCHAPV2      Type = 26
	TYPE_EXTENSIONS    Type = 33
	TYPE_FAST          Type = 43
	TYPE_PAX           Type = 46
	TYPE_PSK           Type = 47
	TYPE_AKA_PRIME     Type = 50
	TYPE_PWD           Type = 52

	TYPE_EXPANDED_TYPE Type = 254
	TYPE_EXPERIMENTAL  Type = 255
)

var TYPE_Values = map[string]Type{
	"MD5":               4,
	"MD5-Challenge":     4,
	"OTP":               5,
	"One-Time-Password": 5,
	"GTC":               6,
	"Generic-Token":     6,
	"TLS":               13,
	"SecurID":           15,
	"LEAP":              17,
	"SIM":               18,
	"TTLS":              21,
	"AKA":               23,
	"PEAP":              25,
	"MSCHAP-V2":         26,
	"FAST":              43,
	"PAX":               46,
	"PSK":               47,
	"AKA-PRIME":         50,
	"PWD":               52,
}

type EAPMessage struct {
	Code       Code
	Identifier uint8
	Length     uint16
	Type       Type
	Value      []byte
}
