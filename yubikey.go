package clevis

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os/exec"
	"strconv"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"golang.org/x/crypto/pbkdf2"
)

// YubikeyPin represents the data yubikey needs to perform decryption
type YubikeyPin struct {
	Type      string     `json:"type"`
	Challenge string     `json:"challenge"`
	Slot      int        `json:"slot"`
	Kdf       YubikeyKdf `json:"kdf"`
}

// YubikeyKdf is the Key Derived Function portion of the YubikeyPin
type YubikeyKdf struct {
	Type       string `json:"type"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iter"`
	Salt       string `json:"salt"`
}

// toConfig ctnverts a given YubikeyPin into the corresponding YubikeyConfig which can be used for encryption
func (p YubikeyPin) toConfig() (YubikeyConfig, error) {
	c := YubikeyConfig{
		Slot: p.Slot,
	}
	return c, nil
}

func (p YubikeyPin) recoverKey() ([]byte, error) {
	switch p.Type {
	case "chalresp":
		return p.challengeResponse()
	default:
		return nil, fmt.Errorf("clevis.go/yubikey: unknown type %s", p.Type)
	}
}

// YubikeyConfig represents the data yubikey needs to perform encryption
type YubikeyConfig struct {
	Slot int `json:"slot"`
}

// NewYubikeyConfig parses the given json-format yubikey config into a YubikeyConfig
func NewYubikeyConfig(config string) (YubikeyConfig, error) {
	var c YubikeyConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return c, err
	}
	return c, nil
}

// EncryptYubikey encrypts a bytestream according to the json-format yubikey config
func EncryptYubikey(data []byte, config string) ([]byte, error) {
	c, err := NewYubikeyConfig(config)
	if err != nil {
		return nil, err
	}
	return c.encrypt(data)
}

// encrypt a bytestream according to the YubikeyConfig
func (c YubikeyConfig) encrypt(data []byte) ([]byte, error) {
	if c.Slot < 1 || c.Slot > 2 {
		return nil, fmt.Errorf("invalid slot value %d", c.Slot)
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	var outBuffer, errBuffer bytes.Buffer
	cmd := exec.Command("ykchalresp", "-i-", "-"+strconv.Itoa(c.Slot))
	cmd.Stdin = bytes.NewReader(challenge)
	cmd.Stdout = &outBuffer
	cmd.Stderr = &errBuffer
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, errBuffer.String())
	}
	// out is hex
	response := outBuffer.Bytes()[:40] // cut the trailing newline
	responseBin := make([]byte, 20)
	if _, err := hex.Decode(responseBin, response); err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	iterations := 1000
	key := pbkdf2.Key(responseBin, salt, iterations, 32, sha256.New)

	hdrs := jwe.NewHeaders()

	clevis := Pin{
		Pin: "yubikey",
		Yubikey: &YubikeyPin{
			Slot:      c.Slot,
			Type:      "chalresp",
			Challenge: base64.RawURLEncoding.EncodeToString(challenge),
			Kdf: YubikeyKdf{
				Type:       "pbkdf2",
				Hash:       "sha256",
				Iterations: iterations,
				Salt:       base64.RawURLEncoding.EncodeToString(salt),
			},
		},
	}
	if err := hdrs.Set("clevis", clevis); err != nil {
		return nil, err
	}

	return jwe.Encrypt(data, jwa.DIRECT, key, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(hdrs))
}

func (p YubikeyPin) challengeResponse() ([]byte, error) {
	challengeBin, err := base64.RawURLEncoding.DecodeString(p.Challenge)
	if err != nil {
		return nil, err
	}
	if len(challengeBin) != 32 {
		return nil, fmt.Errorf("expected challenge length is 32")
	}

	var outBuffer, errBuffer bytes.Buffer
	cmd := exec.Command("ykchalresp", "-i-", "-"+strconv.Itoa(p.Slot))
	cmd.Stdin = bytes.NewReader(challengeBin)
	cmd.Stdout = &outBuffer
	cmd.Stderr = &errBuffer
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, errBuffer.String())
	}
	// out is hex
	response := outBuffer.Bytes()[:40] // cut the trailing newline
	responseBin := make([]byte, 20)
	if _, err := hex.Decode(responseBin, response); err != nil {
		return nil, err
	}

	var key []byte

	switch p.Kdf.Type {
	case "pbkdf2":
		iter := p.Kdf.Iterations
		h := hashByName(p.Kdf.Hash)
		if h == nil {
			return nil, fmt.Errorf("clevis.go/yubikey: unknown hash specified at node 'clevis.yubikey.kdf.hash': %s", p.Kdf.Hash)
		}
		salt, err := base64.RawURLEncoding.DecodeString(p.Kdf.Salt)
		if err != nil {
			return nil, err
		}
		if len(salt) != 32 {
			return nil, fmt.Errorf("expected salt length is 32, got %d", len(salt))
		}

		key = pbkdf2.Key(responseBin, salt, iter, 32, h)
	default:
		return nil, fmt.Errorf("clevis.go/yubikey: unknown kdf type specified at node 'clevis.yubikey.kdf.type': %s", p.Kdf.Type)
	}

	return key, nil
}

func hashByName(name string) func() hash.Hash {
	switch name {
	case "sha256":
		return sha256.New
	case "sha1":
		return sha1.New
	default:
		return nil
	}
}
