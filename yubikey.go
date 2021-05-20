package clevis

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"os/exec"
	"strconv"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"golang.org/x/crypto/pbkdf2"
)

func DecryptYubikey(msg *jwe.Message, clevisNode map[string]interface{}) ([]byte, error) {
	yubikeyNode, ok := clevisNode["yubikey"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("clevis.go/yubikey: cannot parse provided token, node 'clevis.yubikey'")
	}

	yubType, ok := yubikeyNode["type"]
	if !ok {
		return nil, fmt.Errorf("clevis.go/yubikey: cannot parse provided token, node 'clevis.yubikey.type'")
	}

	switch yubType {
	case "chalresp":
		return challengeResponse(msg, yubikeyNode)
	default:
		return nil, fmt.Errorf("clevis.go/yubikey: unknown type %s", yubType)
	}
}

func challengeResponse(msg *jwe.Message, node map[string]interface{}) ([]byte, error) {
	challenge, ok := node["challenge"].(string)
	if !ok {
		return nil, fmt.Errorf("clevis.go/yubikey: cannot parse provided token, node 'clevis.yubikey.challenge'")
	}

	slotNode, ok := node["slot"].(float64)
	if !ok {
		return nil, fmt.Errorf("clevis.go/yubikey: cannot parse provided token, node 'clevis.yubikey.slot'")
	}
	slot := int(slotNode)

	challengeBin, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return nil, err
	}
	if len(challengeBin) != 32 {
		return nil, fmt.Errorf("expected challenge length is 32")
	}

	var outBuffer, errBuffer bytes.Buffer
	cmd := exec.Command("ykchalresp", "-i-", "-"+strconv.Itoa(slot))
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

	kdf, ok := node["kdf"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("clevis.go/yubikey: cannot parse provided token, missing node 'clevis.yubikey.kdf'")
	}

	var key []byte

	switch kdf["type"].(string) {
	case "pbkdf2":
		iter := int(kdf["iter"].(float64))
		h := hashByName(kdf["hash"].(string))
		if h == nil {
			return nil, fmt.Errorf("clevis.go/yubikey: unknown hash specified at node 'clevis.yubikey.kdf.hash': %s", kdf["hash"].(string))
		}
		salt, err := base64.RawURLEncoding.DecodeString(kdf["salt"].(string))
		if err != nil {
			return nil, err
		}
		if len(salt) != 32 {
			return nil, fmt.Errorf("expected salt length is 32, got %d", len(salt))
		}

		key = pbkdf2.Key(responseBin, salt, iter, 32, h)
	default:
		return nil, fmt.Errorf("clevis.go/yubikey: unknown kdf type specified at node 'clevis.yubikey.kdf.type': %s", kdf["type"].(string))
	}

	return msg.Decrypt(jwa.DIRECT, key)
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
