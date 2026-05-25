package clevis

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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

// decryptAEADWithCEK performs the JWE AEAD-decrypt step using a CEK that
// has already been derived by a clevis pin (tang ECDH-ES, tpm2 unseal,
// sss combine, etc.). This bypasses jwx's alg-matching layer, which is
// the source of the RFC 7516 §7.2.1 disjoint-headers rejection on clevis
// JWEs that intentionally carry alg=ECDH-ES (protected) plus alg=dir
// (per-recipient).
//
// rawInput must be the original JWE bytes (compact or JSON form) so the
// AAD computed from the encoded protected header matches what the JWE
// was sealed with. enc is the value of the protected header's "enc"
// field — typically "A256GCM" for clevis.
func decryptAEADWithCEK(rawInput []byte, enc string, cek []byte) ([]byte, error) {
	aad, err := extractEncodedProtectedHeader(rawInput)
	if err != nil {
		return nil, fmt.Errorf("extract protected header: %w", err)
	}

	iv, ct, tag, err := extractEncryptedParts(rawInput)
	if err != nil {
		return nil, fmt.Errorf("extract encrypted parts: %w", err)
	}

	switch enc {
	case "A256GCM":
		return decryptA256GCM(cek, iv, ct, tag, aad)
	default:
		return nil, fmt.Errorf("unsupported JWE enc algorithm: %q", enc)
	}
}

func decryptA256GCM(cek, iv, ct, tag, aad []byte) ([]byte, error) {
	if len(cek) != 32 {
		return nil, fmt.Errorf("A256GCM requires 32-byte CEK, got %d", len(cek))
	}
	if len(iv) != 12 {
		return nil, fmt.Errorf("A256GCM requires 12-byte IV, got %d", len(iv))
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(tag) != aead.Overhead() {
		return nil, fmt.Errorf("A256GCM requires %d-byte tag, got %d", aead.Overhead(), len(tag))
	}
	combined := make([]byte, 0, len(ct)+len(tag))
	combined = append(combined, ct...)
	combined = append(combined, tag...)
	return aead.Open(nil, iv, combined, aad)
}

// extractEncryptedParts returns base64url-decoded iv, ciphertext, tag
// from a JWE in compact or JSON form.
func extractEncryptedParts(rawInput []byte) (iv, ct, tag []byte, err error) {
	trimmed := bytes.TrimSpace(rawInput)
	if len(trimmed) == 0 {
		return nil, nil, nil, fmt.Errorf("empty input")
	}
	var ivB64, ctB64, tagB64 string
	if trimmed[0] == '{' {
		var obj struct {
			IV         string `json:"iv"`
			Ciphertext string `json:"ciphertext"`
			Tag        string `json:"tag"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid JWE JSON: %w", err)
		}
		ivB64, ctB64, tagB64 = obj.IV, obj.Ciphertext, obj.Tag
	} else {
		segs := bytes.Split(trimmed, []byte("."))
		if len(segs) != 5 {
			return nil, nil, nil, fmt.Errorf("invalid JWE compact form")
		}
		ivB64 = string(segs[2])
		ctB64 = string(segs[3])
		tagB64 = string(segs[4])
	}
	if iv, err = base64.RawURLEncoding.DecodeString(ivB64); err != nil {
		return nil, nil, nil, fmt.Errorf("decode iv: %w", err)
	}
	if ct, err = base64.RawURLEncoding.DecodeString(ctB64); err != nil {
		return nil, nil, nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	if tag, err = base64.RawURLEncoding.DecodeString(tagB64); err != nil {
		return nil, nil, nil, fmt.Errorf("decode tag: %w", err)
	}
	return iv, ct, tag, nil
}
