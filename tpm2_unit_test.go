package clevis

import (
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func TestGetAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		want tpm2.Algorithm
	}{
		{"rsa", tpm2.AlgRSA},
		{"sha1", tpm2.AlgSHA1},
		{"sha256", tpm2.AlgSHA256},
		{"sha384", tpm2.AlgSHA384},
		{"sha512", tpm2.AlgSHA512},
		{"ecc", tpm2.AlgECC},
		{"aes", tpm2.AlgAES},
		{"hmac", tpm2.AlgHMAC},
		{"null", tpm2.AlgNull},
		{"cfb", tpm2.AlgCFB},
	}
	for _, tt := range tests {
		got := getAlgorithm(tt.name)
		require.Equal(t, tt.want, got, "getAlgorithm(%q)", tt.name)
	}

	// Unknown algorithm
	require.Equal(t, tpm2.AlgUnknown, getAlgorithm("unknown"))
	require.Equal(t, tpm2.AlgUnknown, getAlgorithm(""))
}

func TestParsePcrIds(t *testing.T) {
	// nil input
	pcrs, err := parsePcrIds(nil)
	require.NoError(t, err)
	require.Nil(t, pcrs)

	// String input
	pcrs, err = parsePcrIds("0,1,7")
	require.NoError(t, err)
	require.Equal(t, []int{0, 1, 7}, pcrs)

	// String with spaces
	pcrs, err = parsePcrIds("0, 1, 7")
	require.NoError(t, err)
	require.Equal(t, []int{0, 1, 7}, pcrs)

	// []int input
	pcrs, err = parsePcrIds([]int{2, 3})
	require.NoError(t, err)
	require.Equal(t, []int{2, 3}, pcrs)

	// []any with float64 (JSON default)
	pcrs, err = parsePcrIds([]any{float64(1), float64(4)})
	require.NoError(t, err)
	require.Equal(t, []int{1, 4}, pcrs)

	// []any with strings
	pcrs, err = parsePcrIds([]any{"2", "5"})
	require.NoError(t, err)
	require.Equal(t, []int{2, 5}, pcrs)

	// []any with mixed types
	pcrs, err = parsePcrIds([]any{float64(1), "3"})
	require.NoError(t, err)
	require.Equal(t, []int{1, 3}, pcrs)

	// Invalid string
	_, err = parsePcrIds("abc")
	require.Error(t, err)

	// Invalid type
	_, err = parsePcrIds(42)
	require.Error(t, err)

	// []any with invalid element
	_, err = parsePcrIds([]any{true})
	require.Error(t, err)

	// Empty []any
	pcrs, err = parsePcrIds([]any{})
	require.NoError(t, err)
	require.Equal(t, []int{}, pcrs)
}

func TestParseTpm2EncrypterConfigInvalid(t *testing.T) {
	_, err := parseTpm2EncrypterConfig("not json")
	require.Error(t, err)
}

func TestParseTpm2DecrypterConfigInvalid(t *testing.T) {
	_, err := parseTpm2DecrypterConfig([]byte("not json"))
	require.Error(t, err)
}

func TestParseTpm2EncrypterConfigDefaults(t *testing.T) {
	e, err := parseTpm2EncrypterConfig(`{}`)
	require.NoError(t, err)
	c, ok := e.(tpm2Encrypter)
	require.True(t, ok)
	// Defaults are applied during encrypt(), not parse, so these should be empty
	require.Equal(t, "", c.Hash)
	require.Equal(t, "", c.Key)
}
