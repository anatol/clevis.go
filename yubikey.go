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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"golang.org/x/crypto/pbkdf2"
)

// yubikeyEncrypter represents the data yubikey needs to perform encryption
type yubikeyEncrypter struct {
	Slot int `json:"slot"`
}

func parseYubikeyEncrypterConfig(config string) (encrypter, error) {
	var c yubikeyEncrypter
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, err
	}
	return c, nil
}

// Encrypt a bytestream according to the yubikeyEncrypter
func (c yubikeyEncrypter) encrypt(data []byte) ([]byte, error) {
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
	responseBytes := bytes.TrimSpace(outBuffer.Bytes())
	if len(responseBytes) != 40 {
		return nil, fmt.Errorf("unexpected ykchalresp response length: got %d", len(responseBytes))
	}
	response := responseBytes[:40]
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

	clevis := map[string]any{
		"pin": "yubikey",
		"yubikey": yubikeyDecrypter{
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
	m, err := json.Marshal(clevis)
	if err != nil {
		return nil, err
	}
	if err := hdrs.Set("clevis", json.RawMessage(m)); err != nil {
		return nil, err
	}

	return jwe.Encrypt(data, jwe.WithKey(jwa.DIRECT(), key), jwe.WithContentEncryption(jwa.A256GCM()), jwe.WithCompress(jwa.NoCompress()), jwe.WithProtectedHeaders(hdrs))
}

// yubikeyDecrypter represents the data yubikey needs to perform decryption
type yubikeyDecrypter struct {
	Type      string     `json:"type"`
	Challenge string     `json:"challenge"`
	Slot      int        `json:"slot"`
	Kdf       YubikeyKdf `json:"kdf"`
}

// YubikeyKdf is the Key Derived Function portion of the yubikeyDecrypter
type YubikeyKdf struct {
	Type       string `json:"type"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iter"`
	Salt       string `json:"salt"`
}

func parseYubikeyDecrypterConfig(config []byte) (decrypter, error) {
	var d yubikeyDecrypter
	if err := json.Unmarshal(config, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (d yubikeyDecrypter) recoverKey(_ *jwe.Message) ([]byte, error) {
	switch d.Type {
	case "chalresp":
		return d.challengeResponse()
	default:
		return nil, fmt.Errorf("unknown type %s", d.Type)
	}
}

func (d yubikeyDecrypter) challengeResponse() ([]byte, error) {
	challengeBin, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil {
		return nil, err
	}
	if len(challengeBin) != 32 {
		return nil, fmt.Errorf("expected challenge length is 32")
	}

	response, err := challengeResponseAllYubikeys(d.Slot, challengeBin)
	if err != nil {
		return nil, err
	}
	responseBin := make([]byte, 20)
	if _, err := hex.Decode(responseBin, response); err != nil {
		return nil, err
	}

	var key []byte

	switch d.Kdf.Type {
	case "pbkdf2":
		iter := d.Kdf.Iterations
		h := hashByName(d.Kdf.Hash)
		if h == nil {
			return nil, fmt.Errorf("unknown hash specified at node 'clevis.yubikey.kdf.hash': %s", d.Kdf.Hash)
		}
		salt, err := base64.RawURLEncoding.DecodeString(d.Kdf.Salt)
		if err != nil {
			return nil, err
		}
		if len(salt) != 32 {
			return nil, fmt.Errorf("expected salt length is 32, got %d", len(salt))
		}

		key = pbkdf2.Key(responseBin, salt, iter, 32, h)
	default:
		return nil, fmt.Errorf("unknown kdf type specified at node 'clevis.yubikey.kdf.type': %s", d.Kdf.Type)
	}

	return key, nil
}

func challengeResponseAllYubikeys(slot int, challenge []byte) ([]byte, error) {
	// This code only uses yubikeyExists() to determine if we should re-attempt challenge-response with another
	// Yubikey.
	//
	// The rationale for not checking for existence first is because that is inherently a race. Take for example:
	//
	// 1. Yubikey 0 and Yubikey 1 plugged in.
	// 2. Loop is at i=1
	// 3. yubikeyExists(1) => true
	// 4. User unplugs Yubikey 1
	// 5. challengeResponseOneYubikey(1, ...) => error
	//
	// It is less racy if we only use existence to check if we should try the next one.
	for i := 0; ; i++ {
		if res, err := challengeResponseOneYubikey(i, slot, challenge); err == nil || !yubikeyExists(i) {
			return res, err
		}
	}
}

func challengeResponseOneYubikey(index, slot int, challenge []byte) ([]byte, error) {
	var outBuffer, errBuffer bytes.Buffer
	cmd := exec.Command("ykchalresp", "-n"+strconv.Itoa(index), "-i-", "-"+strconv.Itoa(slot))
	cmd.Stdin = bytes.NewReader(challenge)
	cmd.Stdout = &outBuffer
	cmd.Stderr = &errBuffer
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, errBuffer.String())
	}
	// out is hex
	responseBytes := bytes.TrimSpace(outBuffer.Bytes())
	if len(responseBytes) != 40 {
		return nil, fmt.Errorf("unexpected ykchalresp response length: got %d", len(responseBytes))
	}
	response := responseBytes[:40]
	return response, nil
}

func yubikeyExists(index int) bool {
	var outBuffer bytes.Buffer
	cmd := exec.Command("ykinfo", "-n"+strconv.Itoa(index), "-a")
	cmd.Stdout = &outBuffer
	cmd.Stderr = &outBuffer
	err := cmd.Run()
	return err == nil
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
