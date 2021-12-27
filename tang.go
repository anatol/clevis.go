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

// TangPin  represents the data tang needs to perform decryption
type TangPin struct {
	Advertisement json.RawMessage `json:"adv"`
	URL           string          `json:"url"`
}

// toConfig converts a given TangPin to the corresponding TangConfig whach can be used for encryption
func (p TangPin) toConfig() (TangConfig, error) {
	c := TangConfig{
		URL: p.URL,
	}

	if p.Advertisement != nil {
		keys, err := jwk.Parse(p.Advertisement)
		if err != nil {
			return c, err
		}
		verifyKeys := filterKeys(keys, jwk.KeyOpVerify)
		if verifyKeys == nil {
			return c, fmt.Errorf("no verify key in the stored advertisement")
		}
		verifyKey := verifyKeys[0] // TODO: find out what verify key is used by default
		thpBytes, err := verifyKey.Thumbprint(defaultThpAlgo)
		if err != nil {
			return c, err
		}
		c.Thumbprint = base64.RawURLEncoding.EncodeToString(thpBytes)
	}

	return c, nil
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

func (p TangPin) recoverKey(msg *jwe.Message) ([]byte, error) {
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

	if err := msg.Recipients()[0].Headers().Set(jwe.AlgorithmKey, jwa.DIRECT); err != nil {
		return nil, err
	}

	return key, nil
}

// TangConfig represents the data needed to perform tang-based encryption
type TangConfig struct {
	// A trusted advertisement (raw JSON or a filename containing JSON)
	Advertisement *json.RawMessage `json:"adv,omitempty"`

	// The base URL of the Tang server (REQUIRED)
	URL string `json:"url"`

	// The thumbprint of a trusted signing key
	Thumbprint string `json:"thp,omitempty"`
}

// NewTangConfig parses the given json-format tang config into a TangConfig
func NewTangConfig(config string) (TangConfig, error) {
	var c TangConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return c, err
	}
	return c, nil
}

var (
	thpAlgos = []crypto.Hash{
		crypto.SHA256, /* S256 */
		crypto.SHA1,   /* S1 */
		crypto.SHA224, /* S224 */
		crypto.SHA384, /* S384 */
		crypto.SHA512, /* S512 */
	}

	defaultThpAlgo = crypto.SHA256
)

// EncryptTang encrypts a bytestream according to the json-format tang config
func EncryptTang(data []byte, config string) ([]byte, error) {
	c, err := NewTangConfig(config)
	if err != nil {
		return nil, err
	}
	return c.encrypt(data)
}

// encrypt a bytestream according to the TangConfig
func (c TangConfig) encrypt(data []byte) ([]byte, error) {
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
		verified, err := verifyThumbprint(verifyKeys, thumbprint)
		if err != nil {
			return nil, err
		}
		if !verified {
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
	advertBytes, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	advert := json.RawMessage(advertBytes)
	header := Pin{
		Pin: "tang",
		Tang: &TangPin{
			URL:           c.URL,
			Advertisement: advert,
		},
	}
	if err := hdrs.Set("clevis", header); err != nil {
		return nil, err
	}

	return jwe.Encrypt(data, jwa.ECDH_ES, exchangeKey, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(hdrs))
}

func verifyThumbprint(verifyKeys []jwk.Key, thumbprint string) (bool, error) {
	thpBytes, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		return false, err
	}

	for _, verifyKey := range verifyKeys {
		for _, a := range thpAlgos {
			thp, err := verifyKey.Thumbprint(a)
			if err != nil {
				return false, err
			}
			if bytes.Equal(thpBytes, thp) {
				return true, nil
			}
		}
	}

	return false, nil
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

func performEcmrExhange(url string, advertizedKeys jwk.Set, serverKeyID string, e jwk.Key) (*ecdsa.PublicKey, error) {
	// JWX does not implement ECMR (used by clevis/jose tool).
	// So we perform ECMR exchange ourselves, construct the EC public key as described here https://github.com/latchset/tang#recovery
	// and then use it as a new ephemeral key in ECDS.
	// For private key used in msg.Decrypt(ECDH_ES) we provide (1,0) thus ECDS multiplication does not modify our new key.
	var epk ecdsa.PublicKey
	if err := e.Raw(&epk); err != nil {
		return nil, err
	}
	webKey, err := lookupKey(advertizedKeys, serverKeyID)
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
	x, y = ecCurve.Add(respKey.X, respKey.Y, x, new(big.Int).Neg(y))

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

// go through keys and find one with thumbprint equal to 'kid'
func lookupKey(keys jwk.Set, kid string) (jwk.Key, error) {
	thumbprint, err := base64.RawURLEncoding.DecodeString(kid)
	if err != nil {
		return nil, err
	}
	var hash crypto.Hash
	switch len(thumbprint) {
	case crypto.SHA256.Size():
		hash = crypto.SHA256
	case crypto.SHA1.Size():
		hash = crypto.SHA1
	default:
		return nil, fmt.Errorf("cannot detect hash algorithm for thumbprint with size %d", len(thumbprint))
	}

	for iter := keys.Iterate(context.TODO()); iter.Next(context.TODO()); {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		thp, err := key.Thumbprint(hash)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(thumbprint, thp) {
			return key, nil
		}
	}

	return nil, nil
}
