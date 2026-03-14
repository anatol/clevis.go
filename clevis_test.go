package clevis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEncrypterConfigUnknownPin(t *testing.T) {
	_, err := parseEncrypterConfig("nonexistent", `{}`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown pin nonexistent")
}

func TestParseDecrypterConfigUnknownPin(t *testing.T) {
	_, err := parseDecrypterConfig("nonexistent", []byte(`{}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown pin nonexistent")
}

func TestDecryptInvalidInput(t *testing.T) {
	// Not valid JWE
	_, err := Decrypt([]byte("not-valid-jwe"))
	require.Error(t, err)

	// Valid JWE-like but missing clevis header - use a minimal JSON structure
	_, err = Decrypt([]byte(`{"protected":"e30","recipients":[{"header":{}}],"ciphertext":"dGVzdA"}`))
	require.Error(t, err)
}
