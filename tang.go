package clevis

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

// tangEncrypter represents the data needed to perform tang-based encryption
type tangEncrypter struct {
	// A trusted advertisement (config JSON or a filename containing JSON)
	Advertisement *json.RawMessage `json:"adv,omitempty"`

	// The base URL of the Tang server (REQUIRED)
	URL string `json:"url"`

	// The thumbprint of a trusted signing key
	Thumbprint string `json:"thp,omitempty"`
}

func parseTangEncrypterConfig(config string) (encrypter, error) {
	var c tangEncrypter
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, err
	}
	return c, nil
}

// Encrypt a bytestream according to the tangEncrypter
func (c tangEncrypter) encrypt(data []byte) ([]byte, error) {
	var path string
	var msgContent []byte

	if c.URL == "" {
		return nil, fmt.Errorf("missing 'url' property")
	}

	thumbprint := c.Thumbprint
	if c.Advertisement == nil {
		// no advertisement provided, fetch one from the server
		resp, err := http.Get(c.URL + "/adv/" + thumbprint)
		if err != nil {
			return nil, err
		}
		msgContent, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(*c.Advertisement, &path); err == nil {
		// advertisement is a file
		msgContent, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	} else {
		msgContent = *c.Advertisement
	}

	msg, err := jws.Parse(msgContent)
	if err != nil {
		return nil, err
	}

	keys, err := jwk.Parse(msg.Payload())
	if err != nil {
		return nil, err
	}

	verifyKeys := filterKeys(keys, jwk.KeyOpVerify)
	if verifyKeys == nil {
		return nil, fmt.Errorf("advertisement is missing signatures")
	}

	for _, key := range verifyKeys {
		if _, err = jws.Verify(msgContent, jwa.SignatureAlgorithm(key.Algorithm()), key); err != nil {
			return nil, err
		}
	}

	if thumbprint != "" {
		k, err := findByThumbprint(verifyKeys, thumbprint)
		if err != nil {
			return nil, err
		}
		if k == nil {
			return nil, fmt.Errorf("trusted JWK '%s' did not sign the advertisement", thumbprint)
		}
	}

	exchangeKeys := filterKeys(keys, jwk.KeyOpDeriveKey)
	if exchangeKeys == nil {
		return nil, fmt.Errorf("no exchange keys found")
	}

	exchangeKey := exchangeKeys[0] // TODO: clarify what derive key is used by clevis

	// we are going to modify the key but 'adv' node should have original keys
	exchangeKey, err = exchangeKey.Clone()
	if err != nil {
		return nil, err
	}

	if err := exchangeKey.Set(jwk.KeyOpsKey, jwk.KeyOperationList{}); err != nil {
		return nil, err
	}
	if err := exchangeKey.Set(jwk.AlgorithmKey, ""); err != nil {
		return nil, err
	}

	thp, err := exchangeKey.Thumbprint(defaultThpAlgo)
	if err != nil {
		return nil, err
	}
	kid := base64.RawURLEncoding.EncodeToString(thp)

	hdrs := jwe.NewHeaders()
	if err := hdrs.Set(jwe.AlgorithmKey, jwa.ECDH_ES); err != nil {
		return nil, err
	}
	if err := hdrs.Set(jwe.ContentEncryptionKey, jwa.A256GCM); err != nil {
		return nil, err
	}
	if err := hdrs.Set(jwe.KeyIDKey, kid); err != nil {
		return nil, err
	}

	clevis := map[string]interface{}{
		"pin": "tang",
		"tang": tangDecrypter{
			URL:           c.URL,
			Advertisement: msg.Payload(),
		},
	}
	m, err := json.Marshal(clevis)
	if err != nil {
		return nil, err
	}
	if err := hdrs.Set("clevis", json.RawMessage(m)); err != nil {
		return nil, err
	}

	return jwe.Encrypt(data, jwa.ECDH_ES, exchangeKey, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(hdrs))
}

// tangDecrypter represents the data tang needs to perform decryption
type tangDecrypter struct {
	Advertisement json.RawMessage `json:"adv"`
	URL           string          `json:"url"`
}

func parseTangDecrypterConfig(config []byte) (decrypter, error) {
	var d tangDecrypter
	if err := json.Unmarshal(config, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (p tangDecrypter) recoverKey(msg *jwe.Message) ([]byte, error) {
	if p.Advertisement == nil {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang.adv'")
	}

	advertizedKeys, err := jwk.Parse(p.Advertisement)
	if err != nil {
		return nil, err
	}

	if p.URL == "" {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang.url'")
	}

	headers := msg.ProtectedHeaders()

	receivedKey, err := performEcmrExhange(p.URL, advertizedKeys, headers.KeyID(), headers.EphemeralPublicKey())
	if err != nil {
		return nil, err
	}

	keysize, err := keySize(headers.ContentEncryption())
	if err != nil {
		return nil, err
	}

	bytesSize := divRoundUp(receivedKey.Curve.Params().BitSize, 8)
	zBytes := expandBuffer(receivedKey.X.Bytes(), bytesSize)

	pubinfo := make([]byte, 4)
	binary.BigEndian.PutUint32(pubinfo, uint32(keysize*8))

	var data []byte
	data = append(data, ndata([]byte(headers.ContentEncryption().String()))...)
	data = append(data, ndata(headers.AgreementPartyUInfo())...)
	data = append(data, ndata(headers.AgreementPartyVInfo())...)
	data = append(data, pubinfo...)

	key := concatKDF(sha256.New(), zBytes, data, keysize)
	return key, nil
}

// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) []byte {
	counterBytes := make([]byte, 4)
	var k []byte
	for counter := uint32(1); len(k) < kdLen; counter++ {
		binary.BigEndian.PutUint32(counterBytes, counter)
		hash.Reset()
		hash.Write(counterBytes)
		hash.Write(z)
		hash.Write(s1)
		k = hash.Sum(k)
	}
	return k[:kdLen]
}

func keySize(alg jwa.ContentEncryptionAlgorithm) (int, error) {
	switch alg {
	case jwa.A128GCM:
		return 16, nil
	case jwa.A192GCM:
		return 24, nil
	case jwa.A256GCM:
		return 32, nil
	case jwa.A128CBC_HS256:
		return 16, nil
	case jwa.A192CBC_HS384:
		return 24, nil
	case jwa.A256CBC_HS512:
		return 32, nil
	default:
		return 0, fmt.Errorf("failed to determine key size for content cipher: invalid algorithm (%s)", alg)
	}
}

func ndata(src []byte) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(src)))
	return append(buf, src...)
}

func performEcmrExhange(url string, advertizedKeys jwk.Set, serverKeyID string, e jwk.Key) (*ecdsa.PublicKey, error) {
	// JWX does not implement ECMR (used by clevis/jose tool).
	// So we perform ECMR exchange ourselves, construct the EC public key as described here https://github.com/latchset/tang#recovery
	// and then use it as a new ephemeral key in ECDS.
	// For private key used in msg.Decrypt(ECDH_ES) we provide (1,0) thus ECDS multiplication does not modify our new key.
	var epk ecdsa.PublicKey
	if err := e.Raw(&epk); err != nil {
		return nil, err
	}
	webKey, err := findByThumbprintInSet(advertizedKeys, serverKeyID)
	if err != nil {
		return nil, err
	}
	var serverKey ecdsa.PublicKey
	if err := webKey.Raw(&serverKey); err != nil {
		return nil, err
	}

	ecCurve := serverKey.Curve // curve used for the key exchange

	if !ecCurve.IsOnCurve(epk.X, epk.Y) {
		return nil, fmt.Errorf("server key is not on the curve %v", ecCurve)
	}

	tempKey, err := ecdsa.GenerateKey(ecCurve, rand.Reader)
	if err != nil {
		return nil, err
	}

	x, y := ecCurve.Add(tempKey.X, tempKey.Y, epk.X, epk.Y)
	xfrKey := &ecdsa.PublicKey{Curve: ecCurve, X: x, Y: y}

	respKey, err := performTangServerRequest(url+"/rec/"+serverKeyID, xfrKey)
	if err != nil {
		return nil, err
	}

	if respKey.Curve != ecCurve {
		return nil, fmt.Errorf("expect EC curve type %v, got %v", ecCurve, respKey.Curve)
	}

	x, y = ecCurve.ScalarMult(serverKey.X, serverKey.Y, tempKey.D.Bytes())
	// resp - tmp
	yy := new(big.Int).Neg(y)
	yy.Mod(yy, ecCurve.Params().P)
	x, y = ecCurve.Add(respKey.X, respKey.Y, x, yy)

	return &ecdsa.PublicKey{Curve: ecCurve, X: x, Y: y}, nil
}

func performTangServerRequest(url string, key *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	reqKey, err := jwk.New(key)
	if err != nil {
		return nil, err
	}
	if err := reqKey.Set(jwk.AlgorithmKey, "ECMR"); err != nil {
		return nil, err
	}

	reqData, err := json.Marshal(reqKey)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/jwk+json", bytes.NewReader(reqData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	respKey, err := jwk.ParseKey(respData)
	if err != nil {
		return nil, err
	}

	var ret ecdsa.PublicKey
	if err := respKey.Raw(&ret); err != nil {
		return nil, err
	}
	return &ret, nil
}

var thpAlgos = map[crypto.Hash]int{
	crypto.SHA256: 32, /* S256 */
	crypto.SHA1:   20, /* S1 */
	crypto.SHA224: 28, /* S224 */
	crypto.SHA384: 48, /* S384 */
	crypto.SHA512: 64, /* S512 */
}

func findByThumbprint(keys []jwk.Key, thumbprint string) (jwk.Key, error) {
	thpBytes, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		return nil, err
	}

	for h, l := range thpAlgos {
		if l != len(thpBytes) {
			continue
		}
		for _, k := range keys {
			thp, err := k.Thumbprint(h)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(thpBytes, thp) {
				return k, nil
			}
		}
	}

	return nil, nil
}

// go through keys and find one with thumbprint equal to 'thumbprint'
func findByThumbprintInSet(keys jwk.Set, thumbprint string) (jwk.Key, error) {
	thpBytes, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		return nil, err
	}

	for h, l := range thpAlgos {
		if l != len(thpBytes) {
			continue
		}
		for iter := keys.Iterate(context.TODO()); iter.Next(context.TODO()); {
			pair := iter.Pair()
			key := pair.Value.(jwk.Key)

			thp, err := key.Thumbprint(h)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(thpBytes, thp) {
				return key, nil
			}
		}
	}

	return nil, nil
}

func filterKeys(set jwk.Set, op jwk.KeyOperation) []jwk.Key {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var keys []jwk.Key

	for iter := set.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		for _, o := range key.KeyOps() {
			if o == op {
				keys = append(keys, key)
			}
		}
	}

	return keys
}
