package clevis

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// extractEncodedProtectedHeader returns the base64url-encoded protected
// header ASCII bytes from a JWE in either compact (5 dot-separated segments)
// or JSON serialization form. The returned slice is the value used as
// Additional Authenticated Data (AAD) when verifying the AEAD tag per
// RFC 7516 §5.1 step 14.
//
// Why we re-parse: jwx's *jwe.Message stores rawProtectedHeaders as an
// unexported field; once you mutate any header via the public API and
// re-marshal, the bytes are re-encoded and differ from the original AAD
// the JWE was signed with. We need the literal original bytes.
func extractEncodedProtectedHeader(input []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty JWE input")
	}
	if trimmed[0] == '{' {
		var obj struct {
			Protected string `json:"protected"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, fmt.Errorf("invalid JWE JSON: %w", err)
		}
		if obj.Protected == "" {
			return nil, fmt.Errorf(`JWE JSON missing "protected" field`)
		}
		return []byte(obj.Protected), nil
	}
	segs := bytes.Split(trimmed, []byte("."))
	if len(segs) != 5 {
		return nil, fmt.Errorf("invalid JWE compact form: expected 5 segments, got %d", len(segs))
	}
	if len(segs[0]) == 0 {
		return nil, fmt.Errorf("JWE compact form has empty protected header")
	}
	return segs[0], nil
}
