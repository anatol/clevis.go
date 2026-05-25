package clevis

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwe"
)

func init() {
	jwe.RegisterCustomField("clevis", json.RawMessage{})
}

// encrypter is an interface to implement pins encrypt functionality
type encrypter interface {
	// Encrypt accepts a plaintext as input and provides encrypted output
	encrypt(input []byte) ([]byte, error)
}

// decrypter is an interface to implement pins decrypt functionality
type decrypter interface {
	// RecoverKey reconstructs a key for the given pin decrypter
	recoverKey(msg *jwe.Message) ([]byte, error)
}

func parseEncrypterConfig(pin, config string) (encrypter, error) {
	switch pin {
	case "tang":
		return parseTangEncrypterConfig(config)
	case "remote":
		return parseRemoteEncrypterConfig(config)
	case "tpm2":
		return parseTpm2EncrypterConfig(config)
	case "sss":
		return parseSssEncrypterConfig(config)
	case "yubikey":
		return parseYubikeyEncrypterConfig(config)
	default:
		// TODO: add custom encrypters from options
		return nil, fmt.Errorf("unknown pin %s", pin)
	}
}

// Encrypt the given data according to the pin type and config config data given.
func Encrypt(input []byte, pin, config string) ([]byte, error) {
	c, err := parseEncrypterConfig(pin, config)
	if err != nil {
		return nil, err
	}
	return c.encrypt(input)
}

// Decrypt decrypts a clevis bound message. The message format can be either compact or JSON.
func Decrypt(input []byte) ([]byte, error) {
	msg, err := jwe.Parse(input)
	if err != nil {
		return nil, err
	}

	var n json.RawMessage
	if err := msg.ProtectedHeaders().Get("clevis", &n); err != nil {
		return nil, fmt.Errorf("provided message does not contain 'clevis' node")
	}

	var node struct {
		Pin string `json:"pin"`
	}

	if err := json.Unmarshal(n, &node); err != nil {
		return nil, err
	}
	pin := node.Pin
	if pin == "" {
		return nil, fmt.Errorf("clevis node does not contain 'pin' property")
	}
	var pins map[string]json.RawMessage
	if err := json.Unmarshal(n, &pins); err != nil {
		return nil, err
	}

	config, ok := pins[pin]
	if !ok || pin == "" {
		return nil, fmt.Errorf("clevis node does not contain property %s", pin)
	}

	d, err := parseDecrypterConfig(pin, config)
	if err != nil {
		return nil, err
	}

	cek, err := d.recoverKey(msg)
	if err != nil {
		return nil, err
	}

	// Extract the content-encryption algorithm from the protected header.
	encAlg, ok := msg.ProtectedHeaders().ContentEncryption()
	if !ok {
		return nil, fmt.Errorf(`JWE protected header missing "enc" field`)
	}

	// Bypass jwx's alg-matching pass: clevis JWEs intentionally carry
	// alg=ECDH-ES (protected) and alg=dir (per-recipient), which jwx v3.1+
	// hard-rejects as an RFC 7516 §7.2.1 disjoint-headers violation. We
	// have the CEK; do the AEAD decrypt directly.
	return decryptAEADWithCEK(input, encAlg.String(), cek)
}

func parseDecrypterConfig(pin string, config []byte) (decrypter, error) {
	switch pin {
	case "tang":
		return parseTangDecrypterConfig(config)
	case "remote":
		return parseRemoteDecrypterConfig(config)
	case "tpm2":
		return parseTpm2DecrypterConfig(config)
	case "sss":
		return parseSssDecrypterConfig(config)
	case "yubikey":
		return parseYubikeyDecrypterConfig(config)
	default:
		// TODO: add custom encrypters from options
		return nil, fmt.Errorf("unknown pin %s", pin)
	}
}
