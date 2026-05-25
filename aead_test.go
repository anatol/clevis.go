package clevis

import (
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
