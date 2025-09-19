package clevis

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
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
	// TODO: turn parseXXXEncrypterConfig into a type parametrized function once 1.18 becomes more widespread
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

	key, err := d.recoverKey(msg)
	if err != nil {
		return nil, err
	}

	// The recovered key is already derived, so we use it as a _direct_ key
	//
	// However, the original message may have been encrypted with a different
	// algorithm (e.g ECDH-ES). Since jwx complains if you try to decrypt
	// a message with a direct key that was encrypted with ECDH-ES, we
	// need to modify the message to use the direct key algorithm.
	if err := msg.Recipients()[0].Headers().Set(jwe.AlgorithmKey, jwa.DIRECT()); err != nil {
		return nil, err
	}

	// Serialize the modified message and re-parse it
	modifiedInput, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// Now try decryption using the direct key on the modified input
	return jwe.Decrypt(modifiedInput, jwe.WithKey(jwa.DIRECT(), key))
}

func parseDecrypterConfig(pin string, config []byte) (decrypter, error) {
	// TODO: turn parseXXXEncrypterConfig into a type parametrized function once 1.18 becomes more widespread
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
