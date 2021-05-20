package clevis

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
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
		jsonForm, err := convertToJsonForm(compactForm)
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
