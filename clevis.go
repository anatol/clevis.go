package clevis

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwe"
)

// Decrypt decrypts a clevis bound message. The message format can be either compact or JSON.
func Decrypt(data []byte) ([]byte, error) {
	if data[0] == '{' {
		var err error
		// https://github.com/lestrrat-go/jwx/issues/230
		data, err = convertToCompact(data)
		if err != nil {
			return nil, err
		}
	}

	msg, err := jwe.Parse(data)
	if err != nil {
		return nil, err
	}

	clevis, ok := msg.Recipients()[0].Headers().PrivateParams()["clevis"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("clevis.go: provided message does not contain 'clevis' node")
	}

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
	default:
		return nil, fmt.Errorf("clevis.go: unknown pin '%v'", pin)
	}
}

func convertToCompact(data []byte) ([]byte, error) {
	var nodes map[string]string
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, err
	}

	var result bytes.Buffer

	// compact for is $protected.$encrypted_key.$iv.$ciphertext.$tag
	result.WriteString(nodes["protected"])
	result.WriteByte('.')
	result.WriteString(nodes["encrypted_key"])
	result.WriteByte('.')
	result.WriteString(nodes["iv"])
	result.WriteByte('.')
	result.WriteString(nodes["ciphertext"])
	result.WriteByte('.')
	result.WriteString(nodes["tag"])

	return result.Bytes(), nil
}
