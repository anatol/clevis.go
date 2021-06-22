package clevis

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
		verifyKey := filterKey(keys, jwk.KeyOpVerify)
		if verifyKey == nil {
			return c, fmt.Errorf("No verify key in the stored advertisement")
		}
		thpBytes, err := verifyKey.Thumbprint(crypto.SHA1)
		if err != nil {
			return c, err
		}
		c.Thumbprint = base64.RawURLEncoding.EncodeToString(thpBytes)
	}

	return c, nil
}

// decrypt a jwe message bound with Tang clevis pin
func (p TangPin) decrypt(msg *jwe.Message) ([]byte, error) {
	if p.Advertisement == nil {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang.adv'")
	}

	advNodeBytes, err := json.Marshal(p.Advertisement)
	if err != nil {
		return nil, err
	}

	advertizedKeys, err := jwk.Parse(advNodeBytes)
	if err != nil {
		return nil, err
	}

	if p.URL == "" {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang.url'")
	}

	headers := msg.Recipients()[0].Headers()

	receivedKey, err := performEcmrExhange(p.URL, advertizedKeys, headers.KeyID(), headers.EphemeralPublicKey())
	if err != nil {
		return nil, err
	}

	if err := headers.Set(jwe.AlgorithmKey, jwa.ECDH_ES); err != nil {
		return nil, err
	}
	newEpk, err := jwk.New(receivedKey)
	if err != nil {
		return nil, err
	}
	if err := headers.Set(jwe.EphemeralPublicKeyKey, newEpk); err != nil {
		return nil, err
	}
	identityKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: receivedKey.Curve,
		},
		D: big.NewInt(1),
	}

	return msg.Decrypt(jwa.ECDH_ES, &identityKey)
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

var thpAlgos = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA1,
}

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

	verifyKey := filterKey(keys, jwk.KeyOpVerify)
	if verifyKey == nil {
		return nil, fmt.Errorf("advertisement is missing signatures")
	}

	if _, err = jws.Verify(msgContent, jwa.SignatureAlgorithm(verifyKey.Algorithm()), verifyKey); err != nil {
		return nil, err
	}

	if thumbprint != "" {
		verified, err := verifyThumbprint(verifyKey, thumbprint)
		if err != nil {
			return nil, err
		}
		if !verified {
			return nil, fmt.Errorf("trusted JWK '%s' did not sign the advertisement", thumbprint)
		}
	}

	exchangeKey := filterKey(keys, jwk.KeyOpDeriveKey)
	if exchangeKey == nil {
		return nil, fmt.Errorf("no exchange keys found")
	}

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

	thp, err := exchangeKey.Thumbprint(crypto.SHA256)
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

func verifyThumbprint(verifyKey jwk.Key, thumbprint string) (bool, error) {
	thpBytes, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		return false, err
	}

	for _, a := range thpAlgos {
		thp, err := verifyKey.Thumbprint(a)
		if err != nil {
			return false, err
		}
		if bytes.Equal(thpBytes, thp) {
			return true, nil
		}
	}

	return false, nil
}

func filterKey(set jwk.Set, op jwk.KeyOperation) jwk.Key {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for iter := set.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		for _, o := range key.KeyOps() {
			if o == op {
				return key
			}
		}
	}

	return nil
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
