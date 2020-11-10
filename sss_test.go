package clevis

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestDecryptSss(t *testing.T) {
	const num = 5
	const threshold = 3

	var servers [num]*TangServer

	for i := range servers {
		s, err := NewTangServer(t)
		if err != nil {
			t.Fatal(err)
		}
		servers[i] = s
		defer s.Stop()
	}

	const inputText = "testing Shamir Secret Sharing"

	// encrypt a text using 'clevis-encrypt-sss' like this:
	// clevis-encrypt-sss '{"t":1, "pins": {"tang": [{"url":"router.lan:8888"},{"url":"router.lan:8888"}]}}' <<< "test"
	var tangConfigs [num]string
	for i, s := range servers {
		tangConfigs[i] = s.TangConfig()
	}
	sssConfig := fmt.Sprintf(`{"t":%d, "pins": {"tang": [%s]}}`, threshold, strings.Join(tangConfigs[:], ","))
	encryptCmd := exec.Command("/usr/bin/clevis-encrypt-sss", sssConfig)
	encryptCmd.Stdin = strings.NewReader(inputText)
	var encryptedData bytes.Buffer
	encryptCmd.Stdout = &encryptedData
	if err := encryptCmd.Run(); err != nil {
		t.Fatal(err)
	}

	compactForm := encryptedData.Bytes()
	jsonForm, err := convertToJsonForm(compactForm)
	if err != nil {
		t.Fatal(err)
	}

	// decrypt this text using our implementation
	plaintext1, err := Decrypt(compactForm)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext1) != inputText {
		t.Fatalf("sss decryption failed: expected '%s', got '%s'", inputText, string(plaintext1))
	}

	plaintext2, err := Decrypt(jsonForm)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext2) != inputText {
		t.Fatalf("sss decryption failed: expected '%s', got '%s'", inputText, string(plaintext2))
	}
}
