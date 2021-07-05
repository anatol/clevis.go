package clevis

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptYubikey(t *testing.T) {
	inputText := "testing yubikey"

	clevisConfigs := []string{
		`{"slot":2}`,
	}

	for _, c := range clevisConfigs {
		var outbuf bytes.Buffer
		cmd := exec.Command("./clevis-encrypt-yubikey", c)
		cmd.Stdin = strings.NewReader(inputText)
		cmd.Stdout = &outbuf
		cmd.Stderr = os.Stderr
		require.NoError(t, cmd.Run())

		compactForm := outbuf.Bytes()
		jsonForm, err := convertToJSONForm(compactForm)
		require.NoError(t, err)

		// decrypt compact form using our implementation
		plaintext1, err := Decrypt(compactForm)
		require.NoError(t, err)
		require.Equal(t, inputText, string(plaintext1), "compact tpm2 decryption failed")

		// decrypt json form using our implementation
		plaintext2, err := Decrypt(jsonForm)
		require.NoError(t, err)
		require.Equal(t, inputText, string(plaintext2), "json tpm2 decryption failed")
	}
}

func TestEncryptYubikey(t *testing.T) {
	inputText := "testing yubikey"

	clevisConfigs := []string{
		`{"slot":2}`,
	}

	for _, c := range clevisConfigs {
		encrypted, err := EncryptYubikey([]byte(inputText), c)
		require.NoError(t, err)

		decrypted1, err := Decrypt(encrypted)
		require.NoError(t, err)
		require.Equal(t, inputText, string(decrypted1), "decrypt failed")

		var outbuf bytes.Buffer
		cmd := exec.Command("./clevis-decrypt-yubikey")
		cmd.Stdin = bytes.NewReader(encrypted)
		cmd.Stdout = &outbuf
		cmd.Stderr = os.Stderr
		require.NoError(t, cmd.Run())
		decrypted2 := outbuf.Bytes()
		require.Equal(t, inputText, string(decrypted2), "decrypt failed")
	}
}

func TestYubikeyToConfig(t *testing.T) {
	var tests = []struct {
		pin      YubikeyPin
		expected YubikeyConfig
	}{{
		pin:      YubikeyPin{},
		expected: YubikeyConfig{},
	}, {
		pin: YubikeyPin{
			Type:      "type",
			Challenge: "challenge",
			Slot:      42,
		},
		expected: YubikeyConfig{
			Slot: 42,
		},
	}}

	for _, test := range tests {
		c, err := test.pin.toConfig()
		assert.NoError(t, err)
		assert.Equal(t, test.expected, c)
	}
}
