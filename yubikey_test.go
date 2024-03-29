package clevis

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func yubikeyPresents() bool {
	out, err := exec.Command("lsusb").CombinedOutput()
	if err != nil {
		return false
	}

	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "Yubikey") {
			return true
		}
	}

	return false
}

func TestDecryptYubikey(t *testing.T) {
	if !yubikeyPresents() {
		t.Skip("no yubikey found")
	}

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
	if !yubikeyPresents() {
		t.Skip("no yubikey found")
	}

	inputText := "testing yubikey"

	clevisConfigs := []string{
		`{"slot":2}`,
	}

	for _, c := range clevisConfigs {
		encrypted, err := Encrypt([]byte(inputText), "yubikey", c)
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
