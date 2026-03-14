package clevis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSssEncrypterConfigInvalid(t *testing.T) {
	_, err := parseSssEncrypterConfig("not json")
	require.Error(t, err)
}

func TestParseSssDecrypterConfigInvalid(t *testing.T) {
	_, err := parseSssDecrypterConfig([]byte("not json"))
	require.Error(t, err)
}

func TestParseSssEncrypterConfig(t *testing.T) {
	e, err := parseSssEncrypterConfig(`{"t":2,"pins":{"tang":[{"url":"http://localhost"}]}}`)
	require.NoError(t, err)
	c, ok := e.(sssEncrypter)
	require.True(t, ok)
	require.Equal(t, 2, c.Threshold)
	require.Contains(t, c.Pins, "tang")
}

func TestSssEncryptInvalidThreshold(t *testing.T) {
	c := sssEncrypter{Threshold: 0}
	_, err := c.encrypt([]byte("test"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid threshold")
}
