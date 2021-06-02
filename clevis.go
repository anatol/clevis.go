package clevis

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwe"
)

// Decrypt decrypts a clevis bound message. The message format can be either compact or JSON.
func Decrypt(data []byte) ([]byte, error) {
	msg, err := jwe.Parse(data)
	if err != nil {
		return nil, err
	}

	n, ok := msg.ProtectedHeaders().Get("clevis")
	if !ok {
		return nil, fmt.Errorf("clevis.go: provided message does not contain 'clevis' node")
	}
	clevis := n.(map[string]interface{})

	pin, ok := clevis["pin"].(string)
	if !ok {
		return nil, fmt.Errorf("clevis.go: provided message does not contain 'clevis.pin' node")
	}

	switch pin {
	case "tang":
		return DecryptTang(msg, clevis)
	case "sss":
		return DecryptSss(msg, clevis)
	case "tpm2":
		return DecryptTpm2(msg, clevis)
	case "yubikey":
		return DecryptYubikey(msg, clevis)
	default:
		return nil, fmt.Errorf("clevis.go: unknown pin '%v'", pin)
	}
}
