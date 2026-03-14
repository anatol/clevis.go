package clevis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRemoteEncrypterConfigInvalid(t *testing.T) {
	_, err := parseRemoteEncrypterConfig("not json")
	require.Error(t, err)
}

func TestParseRemoteDecrypterConfigInvalid(t *testing.T) {
	_, err := parseRemoteDecrypterConfig([]byte("not json"))
	require.Error(t, err)
}

func TestParseRemoteEncrypterConfigDefaultPort(t *testing.T) {
	e, err := parseRemoteEncrypterConfig(`{}`)
	require.NoError(t, err)
	c, ok := e.(remoteEncrypter)
	require.True(t, ok)
	require.Equal(t, remoteDefaultPort, c.Port)
}

func TestParseRemoteEncrypterConfigCustomPort(t *testing.T) {
	e, err := parseRemoteEncrypterConfig(`{"port":9999}`)
	require.NoError(t, err)
	c, ok := e.(remoteEncrypter)
	require.True(t, ok)
	require.Equal(t, 9999, c.Port)
}

func TestRemoteEncryptNoAdvertisement(t *testing.T) {
	c := remoteEncrypter{Port: 8609}
	_, err := c.encrypt([]byte("test"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "no advertisement")
}
