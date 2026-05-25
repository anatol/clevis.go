package clevis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtractEncodedProtectedHeaderCompact verifies extraction from a 5-segment
// compact JWE.
func TestExtractEncodedProtectedHeaderCompact(t *testing.T) {
	// header.encryptedKey.iv.ciphertext.tag, with arbitrary base64url content.
	input := []byte("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9.ek.iv.ct.tag")
	got, err := extractEncodedProtectedHeader(input)
	require.NoError(t, err)
	require.Equal(t, []byte("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9"), got)
}

// TestExtractEncodedProtectedHeaderJSON verifies extraction from the JWE
// JSON serialization (multi-recipient form).
func TestExtractEncodedProtectedHeaderJSON(t *testing.T) {
	input := []byte(`{"protected":"eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9","recipients":[{"header":{"alg":"dir"}}],"iv":"AAAA","ciphertext":"BBBB","tag":"CCCC"}`)
	got, err := extractEncodedProtectedHeader(input)
	require.NoError(t, err)
	require.Equal(t, []byte("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9"), got)
}

// TestExtractEncodedProtectedHeaderInvalidCompact rejects malformed compact form.
func TestExtractEncodedProtectedHeaderInvalidCompact(t *testing.T) {
	cases := []string{
		"only.three.segments", // not 5 segments, not JSON
		"",                    // empty
		"....",                // 5 segments but all empty — header empty is invalid
	}
	for _, c := range cases {
		_, err := extractEncodedProtectedHeader([]byte(c))
		require.Error(t, err, "input=%q should fail", c)
		require.True(t, strings.Contains(err.Error(), "invalid") ||
			strings.Contains(err.Error(), "empty"),
			"input=%q err=%v", c, err)
	}
}

// TestExtractEncodedProtectedHeaderJSONMissing rejects JSON missing "protected".
func TestExtractEncodedProtectedHeaderJSONMissing(t *testing.T) {
	input := []byte(`{"iv":"AAAA","ciphertext":"BBBB","tag":"CCCC"}`)
	_, err := extractEncodedProtectedHeader(input)
	require.Error(t, err)
}

// TestDecryptAEADWithCEK_A256GCM round-trips a known AES-256-GCM payload
// using the exact same AAD-as-protected-header layout we'll use in
// production.
func TestDecryptAEADWithCEK_A256GCM(t *testing.T) {
	cek := make([]byte, 32)
	_, _ = rand.Read(cek)

	iv := make([]byte, 12)
	_, _ = rand.Read(iv)

	plaintext := []byte("hello, clevis!")
	aad := []byte("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9")

	block, err := aes.NewCipher(cek)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	ctAndTag := aead.Seal(nil, iv, plaintext, aad)
	ct := ctAndTag[:len(ctAndTag)-aead.Overhead()]
	tag := ctAndTag[len(ctAndTag)-aead.Overhead():]

	jwe := mustJSON(map[string]string{
		"protected":  string(aad),
		"iv":         base64.RawURLEncoding.EncodeToString(iv),
		"ciphertext": base64.RawURLEncoding.EncodeToString(ct),
		"tag":        base64.RawURLEncoding.EncodeToString(tag),
	})

	got, err := decryptAEADWithCEK(jwe, "A256GCM", cek)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestDecryptAEADWithCEK_TamperedAAD rejects when AAD doesn't match.
func TestDecryptAEADWithCEK_TamperedAAD(t *testing.T) {
	cek := make([]byte, 32)
	_, _ = rand.Read(cek)
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	plaintext := []byte("payload")
	originalAAD := []byte("eyJhbGciOiJFQ0RILUVTIn0")

	block, _ := aes.NewCipher(cek)
	aead, _ := cipher.NewGCM(block)
	ctAndTag := aead.Seal(nil, iv, plaintext, originalAAD)
	ct := ctAndTag[:len(ctAndTag)-aead.Overhead()]
	tag := ctAndTag[len(ctAndTag)-aead.Overhead():]

	jwe := mustJSON(map[string]string{
		"protected":  "eyJhbGciOiJkaXIifQ", // tampered
		"iv":         base64.RawURLEncoding.EncodeToString(iv),
		"ciphertext": base64.RawURLEncoding.EncodeToString(ct),
		"tag":        base64.RawURLEncoding.EncodeToString(tag),
	})

	_, err := decryptAEADWithCEK(jwe, "A256GCM", cek)
	require.Error(t, err)
}

// TestDecryptAEADWithCEK_UnsupportedEnc returns a clear error.
func TestDecryptAEADWithCEK_UnsupportedEnc(t *testing.T) {
	_, err := decryptAEADWithCEK([]byte(`{"protected":"x","iv":"AAAA","ciphertext":"BBBB","tag":"CCCC"}`), "ChaCha20", []byte("k"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
