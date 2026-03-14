package clevis

import (
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashByName(t *testing.T) {
	h := hashByName("sha256")
	require.NotNil(t, h)
	require.Equal(t, sha256.New().Size(), h().Size())

	h = hashByName("sha1")
	require.NotNil(t, h)
	require.Equal(t, sha1.New().Size(), h().Size())

	h = hashByName("unknown")
	require.Nil(t, h)

	h = hashByName("")
	require.Nil(t, h)
}

func TestParseYubikeyEncrypterConfigInvalid(t *testing.T) {
	_, err := parseYubikeyEncrypterConfig("not json")
	require.Error(t, err)
}

func TestParseYubikeyDecrypterConfigInvalid(t *testing.T) {
	_, err := parseYubikeyDecrypterConfig([]byte("not json"))
	require.Error(t, err)
}

func TestParseYubikeyEncrypterConfig(t *testing.T) {
	e, err := parseYubikeyEncrypterConfig(`{"slot":2}`)
	require.NoError(t, err)
	c, ok := e.(yubikeyEncrypter)
	require.True(t, ok)
	require.Equal(t, 2, c.Slot)
}
