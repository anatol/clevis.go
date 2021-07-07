package clevis

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwe"
)

// Pin represents the structured clevis data which can be used to decrypt the jwe message
type Pin struct {
	Pin     string      `json:"pin"`
	Tang    *TangPin    `json:"tang,omitempty"`
	Tpm2    *Tpm2Pin    `json:"tpm2,omitempty"`
	Sss     *SssPin     `json:"sss,omitempty"`
	Yubikey *YubikeyPin `json:"yubikey,omitempty"`
}

func init() {
	jwe.RegisterCustomField("clevis", Pin{})
}

// Parse the bytestream into a jwe.Message and clevis.Pin
func Parse(data []byte) (*jwe.Message, *Pin, error) {
	msg, err := jwe.Parse(data)
	if err != nil {
		return nil, nil, err
	}

	pin, err := pinFromMsg(msg)
	if err != nil {
		return msg, nil, err
	}
	return msg, pin, err
}

func pinFromMsg(msg *jwe.Message) (*Pin, error) {
	n, ok := msg.ProtectedHeaders().Get("clevis")
	if !ok {
		return nil, fmt.Errorf("clevis.go: provided message does not contain 'clevis' node")
	}
	pin := n.(Pin)
	return &pin, nil
}

// Config represents the structured clevis data which can be used to encrypt a []byte
type Config struct {
	Pin     string         `json:"pin"`
	Tang    *TangConfig    `json:"tang,omitempty"`
	Tpm2    *Tpm2Config    `json:"tpm2,omitempty"`
	Sss     *SssConfig     `json:"sss,omitempty"`
	Yubikey *YubikeyConfig `json:"yubikey,omitempty"`
}

// ExtractConfig creates a Config struct that corresponds to an existing enceypted payload.  This can be used to encrypt something else in exactly the same way.
func ExtractConfig(data []byte) (Config, error) {
	_, pin, err := Parse(data)
	if err != nil {
		return Config{}, err
	}
	return pin.ToConfig()
}

// ToConfig converts a clevis.Pin to the matching clevis.Config that can be used to encrypt something else in exactly the same way.
func (p Pin) ToConfig() (Config, error) {
	c := Config{
		Pin: p.Pin,
	}
	switch c.Pin {
	case "tang":
		cfg, err := p.Tang.toConfig()
		if err != nil {
			return c, err
		}
		c.Tang = &cfg
	case "tpm2":
		cfg, err := p.Tpm2.toConfig()
		if err != nil {
			return c, err
		}
		c.Tpm2 = &cfg
	case "sss":
		cfg, err := p.Sss.toConfig()
		if err != nil {
			return c, err
		}
		c.Sss = &cfg
	case "yubikey":
		cfg, err := p.Yubikey.toConfig()
		if err != nil {
			return c, err
		}
		c.Yubikey = &cfg
	default:
		return c, fmt.Errorf("clevis.go: unknown pin '%v'", p.Pin)
	}
	return c, nil
}

// Decrypt decrypts a clevis bound message. The message format can be either compact or JSON.
func Decrypt(data []byte) ([]byte, error) {
	return jwe.Decrypt(data, "", nil, jwe.WithPostParser(clevisParser{}))
}

type clevisParser struct{}

// Do implements a jwe.PostParser interface which must use the excracted pin config to set up the decryprion algorithm and key
func (clevisParser) Do(ctx jwe.DecryptCtx) error {
	p, err := pinFromMsg(ctx.Message())
	if err != nil {
		return err
	}

	switch p.Pin {
	case "tang":
		err = p.Tang.prepareDecryptionCtx(ctx)
	case "sss":
		err = p.Sss.prepareDecryptionCtx(ctx)
	case "tpm2":
		err = p.Tpm2.prepareDecryptionCtx(ctx)
	case "yubikey":
		err = p.Yubikey.prepareDecryptionCtx(ctx)
	default:
		err = fmt.Errorf("clevis.go: unknown pin '%v'", p.Pin)
	}
	if err != nil {
		return err
	}

	if ctx.Algorithm() == "" || ctx.Key() == nil {
		return fmt.Errorf("clevis.go: %s did not setup the algorithm and key", p.Pin)
	}
	return nil
}

// Encrypt the given data according to the pin type and raw config data given.
func Encrypt(data []byte, pin string, config string) ([]byte, error) {
	c := Config{
		Pin: pin,
	}
	switch pin {
	case "tang":
		cfg, err := NewTangConfig(config)
		if err != nil {
			return nil, err
		}
		c.Tang = &cfg
	case "tpm2":
		cfg, err := NewTpm2Config(config)
		if err != nil {
			return nil, err
		}
		c.Tpm2 = &cfg
	case "sss":
		cfg, err := NewSssConfig(config)
		if err != nil {
			return nil, err
		}
		c.Sss = &cfg
	case "yubikey":
		cfg, err := NewYubikeyConfig(config)
		if err != nil {
			return nil, err
		}
		c.Yubikey = &cfg
	}
	return c.Encrypt(data)
}

// Encrypt the given data according to the clevis.Config
func (c Config) Encrypt(data []byte) ([]byte, error) {
	switch c.Pin {
	case "tang":
		return c.Tang.encrypt(data)
	case "sss":
		return c.Sss.encrypt(data)
	case "tpm2":
		return c.Tpm2.encrypt(data)
	case "yubikey":
		return c.Yubikey.encrypt(data)
	default:
		return nil, fmt.Errorf("clevis.go: unknown pin '%v'", c.Pin)
	}
}

// Encrypt the given data according to the given clevis.Pin
func (p Pin) Encrypt(data []byte) ([]byte, error) {
	c, err := p.ToConfig()
	if err != nil {
		return nil, err
	}
	return c.Encrypt(data)
}
