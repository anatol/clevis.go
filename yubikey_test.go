package clevis

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}

		compactForm := outbuf.Bytes()
		jsonForm, err := convertToJSONForm(compactForm)
		if err != nil {
			t.Fatal(err)
		}

		// decrypt compact form using our implementation
		plaintext1, err := Decrypt(compactForm)
		if err != nil {
			t.Fatal(err)
		}
		if string(plaintext1) != inputText {
			t.Fatalf("tpm2 decryption failed: expected '%s', got '%s'", inputText, string(plaintext1))
		}

		// decrypt json form using our implementation
		plaintext2, err := Decrypt(jsonForm)
		if err != nil {
			t.Fatal(err)
		}
		if string(plaintext2) != inputText {
			t.Fatalf("tpm2 decryption failed: expected '%s', got '%s'", inputText, string(plaintext2))
		}
	}
}

func TestEncryptYubikey(t *testing.T) {
	inputText := "testing yubikey"

	clevisConfigs := []string{
		`{"slot":2}`,
	}

	for _, c := range clevisConfigs {
		encrypted, err := EncryptYubikey([]byte(inputText), c)
		if err != nil {
			t.Fatal(err)
		}

		decrypted1, err := Decrypt(encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if string(decrypted1) != inputText {
			t.Fatalf("unable decrypt data: expected %s, got %s", inputText, string(decrypted1))
		}

		var outbuf bytes.Buffer
		cmd := exec.Command("./clevis-decrypt-yubikey")
		cmd.Stdin = bytes.NewReader(encrypted)
		cmd.Stdout = &outbuf
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		decrypted2 := outbuf.Bytes()
		if string(decrypted2) != inputText {
			t.Fatalf("unable decrypt data: expected %s, got %s", inputText, string(decrypted2))
		}
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
