package clevis

import (
	"bytes"
	"fmt"
	"github.com/anatol/tang.go"
	"github.com/stretchr/testify/require"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestReverseTang(t *testing.T) {
	t.Parallel()

	const inputText = "some plaintext foobar"

	// generate server keys
	keysDir := t.TempDir()
	require.NoError(t, exec.Command(tangBinLocation+"tangd-keygen", keysDir, "sign", "exchange").Run())
	ks, err := tang.ReadKeys(keysDir)
	require.NoError(t, err)

	// encrypt a text using 'clevis-encrypt-reverse-tang' like this:
	// clevis-encrypt-reverse-tang '{"adv":"..."}' <<< "hello"
	config := fmt.Sprintf(`{"adv": %s, "port": 16798}`, ks.DefaultAdvertisement)
	encryptCmd := exec.Command("./clevis-encrypt-reverse-tang", config)
	encryptCmd.Stdin = strings.NewReader(inputText)
	var encryptedData bytes.Buffer
	encryptCmd.Stdout = &encryptedData
	if testing.Verbose() {
		encryptCmd.Stderr = os.Stderr
	}
	require.NoError(t, encryptCmd.Run())

	go func() {
		// decrypt this text using our implementation
		plaintext, err := Decrypt(encryptedData.Bytes())
		require.NoError(t, err)
		require.Equal(t, inputText, string(plaintext), "decryption failed")
	}()

	time.Sleep(time.Second) // wait till .Decrypt() starts TCP server
	require.NoError(t, tang.ReverseTangHandshake(":16798", ks))
}