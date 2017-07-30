//go:generate go run cmd/radius-dict-gen/main.go -package rfc2865 -output rfc2865/generated.go /usr/share/freeradius/dictionary.rfc2865
//go:generate go run cmd/radius-dict-gen/main.go -package rfc2866 -output rfc2866/generated.go /usr/share/freeradius/dictionary.rfc2866
//go:generate go run cmd/radius-dict-gen/main.go -package rfc2867 -output rfc2867/generated.go -ref Acct-Status-Type:layeh.com/radius/rfc2866 /usr/share/freeradius/dictionary.rfc2867

package radius