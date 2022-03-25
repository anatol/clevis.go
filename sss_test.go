package clevis

import (
	"bytes"
	"crypto"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecryptSss(t *testing.T) {
	const num = 5
	const threshold = 3

	var servers [num]*tangServer

	for i := range servers {
		s, err := newTangServer(t.TempDir())
		require.NoError(t, err)
		servers[i] = s
		defer s.Stop()
	}

	const inputText = "testing Shamir Secret Sharing"

	// encrypt a text using 'clevis-encrypt-sss' like this:
	// clevis-encrypt-sss '{"t":1, "pins": {"tang": [{"url":"router.lan:8888"},{"url":"router.lan:8888"}]}}' <<< "test"
	var tangConfigs [num]string
	for i, s := range servers {
		config, err := s.TangConfig(crypto.SHA256, "http://localhost")
		require.NoError(t, err)
		tangConfigs[i] = config
	}
	sssConfig := fmt.Sprintf(`{"t":%d, "pins": {"tang": [%s]}}`, threshold, strings.Join(tangConfigs[:], ","))
	encryptCmd := exec.Command("clevis-encrypt-sss", sssConfig)
	encryptCmd.Stdin = strings.NewReader(inputText)
	var encryptedData bytes.Buffer
	encryptCmd.Stdout = &encryptedData
	if testing.Verbose() {
		encryptCmd.Stderr = os.Stderr
	}
	require.NoError(t, encryptCmd.Run())

	compactForm := encryptedData.Bytes()
	jsonForm, err := convertToJSONForm(compactForm)
	require.NoError(t, err)

	// decrypt this text using our implementation
	plaintext1, err := Decrypt(compactForm)
	require.NoError(t, err)
	require.Equal(t, inputText, string(plaintext1), "decryption failed")

	plaintext2, err := Decrypt(jsonForm)
	require.NoError(t, err)
	require.Equal(t, inputText, string(plaintext2), "decryption failed")
}

func TestEncryptSss(t *testing.T) {
	const num = 5
	const threshold = 3

	var servers [num]*tangServer

	for i := range servers {
		s, err := newTangServer(t.TempDir())
		require.NoError(t, err)
		servers[i] = s
		defer s.Stop()
	}

	const inputText = "testing Shamir Secret Sharing encryption"

	// encrypt a text using 'clevis-encrypt-sss' like this:
	// clevis-encrypt-sss '{"t":1, "pins": {"tang": [{"url":"router.lan:8888"},{"url":"router.lan:8888"}]}}' <<< "test"
	var tangConfigs [num]string
	for i, s := range servers {
		config, err := s.TangConfig(crypto.SHA256, "http://localhost")
		require.NoError(t, err)
		tangConfigs[i] = config
	}
	sssConfig := fmt.Sprintf(`{"t":%d, "pins": {"tang": [%s]}}`, threshold, strings.Join(tangConfigs[:], ","))
	encrypted, err := Encrypt([]byte(inputText), "sss", sssConfig)
	require.NoError(t, err)

	decryptedData1, err := Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, inputText, string(decryptedData1), "decryption failed")

	decryptCmd := exec.Command("clevis-decrypt-sss")
	decryptCmd.Stdin = bytes.NewReader(encrypted)
	var decryptedData2 bytes.Buffer
	decryptCmd.Stdout = &decryptedData2
	if testing.Verbose() {
		decryptCmd.Stderr = os.Stderr
	}
	require.NoError(t, decryptCmd.Run())
	require.Equal(t, inputText, decryptedData2.String(), "decryption failed")
}
