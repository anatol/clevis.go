package clevis

import (
	"crypto/sha256"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

func TestKeySize(t *testing.T) {
	tests := []struct {
		alg  jwa.ContentEncryptionAlgorithm
		want int
	}{
		{jwa.A128GCM(), 16},
		{jwa.A192GCM(), 24},
		{jwa.A256GCM(), 32},
		{jwa.A128CBC_HS256(), 16},
		{jwa.A192CBC_HS384(), 24},
		{jwa.A256CBC_HS512(), 32},
	}
	for _, tt := range tests {
		size, err := keySize(tt.alg)
		require.NoError(t, err)
		require.Equal(t, tt.want, size)
	}
}

func TestNdata(t *testing.T) {
	// ndata should prepend a 4-byte big-endian length
	result := ndata([]byte("ABC"))
	require.Equal(t, []byte{0, 0, 0, 3, 'A', 'B', 'C'}, result)

	result = ndata([]byte{})
	require.Equal(t, []byte{0, 0, 0, 0}, result)
}

func TestConcatKDFDeterministic(t *testing.T) {
	// Same inputs should produce same outputs
	k1 := concatKDF(sha256.New(), []byte("secret"), []byte("info"), 32)
	k2 := concatKDF(sha256.New(), []byte("secret"), []byte("info"), 32)
	require.Equal(t, k1, k2)
	require.Len(t, k1, 32)

	// Different inputs should produce different outputs
	k3 := concatKDF(sha256.New(), []byte("other"), []byte("info"), 32)
	require.NotEqual(t, k1, k3)

	// Different requested lengths
	k16 := concatKDF(sha256.New(), []byte("secret"), []byte("info"), 16)
	require.Len(t, k16, 16)
	require.Equal(t, k1[:16], k16)
}

func TestFindByThumbprintEmpty(t *testing.T) {
	// Empty key list should return nil, nil
	k, err := findByThumbprint(nil, "AAAA")
	require.NoError(t, err)
	require.Nil(t, k)
}

func TestParseTangEncrypterConfigInvalid(t *testing.T) {
	_, err := parseTangEncrypterConfig("not json")
	require.Error(t, err)
}
