package clevis

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
)

// DecryptTang decrypts a jwe message bound with Tang clevis pin
func DecryptTang(msg *jwe.Message, clevisNode map[string]interface{}) ([]byte, error) {
	tangNode, ok := clevisNode["tang"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang'")
	}

	recipient := msg.Recipients()[0]
	keyId := recipient.Headers().KeyID()

	// JWX does not implement ECMR (used by clevis/jose tool).
	// So we perform ECMR exchange ourselves, construct the EC public key as described here https://github.com/latchset/tang#recovery
	// and then use it as a new ephemeral key in ECDS.
	// For private key used in msg.Decrypt(ECDH_ES) we provide (1,0) thus ECDS multiplication does not modify our new key.
	var epk ecdsa.PublicKey
	if err := recipient.Headers().EphemeralPublicKey().Raw(&epk); err != nil {
		return nil, err
	}
	receivedKey, err := performEcmrExhange(tangNode, keyId, &epk)
	if err != nil {
		return nil, err
	}

	if err := recipient.Headers().Set(jwe.AlgorithmKey, jwa.ECDH_ES); err != nil {
		return nil, err
	}
	newEpk, err := jwk.New(receivedKey)
	if err != nil {
		return nil, err
	}
	if err := recipient.Headers().Set(jwe.EphemeralPublicKeyKey, newEpk); err != nil {
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

func performEcmrExhange(tangNode map[string]interface{}, serverKeyId string, epk *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	advNode, ok := tangNode["adv"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang.adv'")
	}

	urlNode, ok := tangNode["url"].(string)
	if !ok {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang.url'")
	}

	serverKey, err := findKey(advNode, serverKeyId) // foundKey is the same as 'srv'
	if err != nil {
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

	respKey, err := performTangServerRequest(urlNode+"/rec/"+serverKeyId, xfrKey)
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

	respData, err := ioutil.ReadAll(resp.Body)
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
func findKey(advNode map[string]interface{}, kid string) (*ecdsa.PublicKey, error) {
	keys := advNode["keys"].([]interface{})
	for _, k := range keys {
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}

		webKey, err := jwk.ParseKey(keyBytes)
		if err != nil {
			return nil, err
		}

		thp, err := webKey.Thumbprint(crypto.SHA1)
		if err != nil {
			return nil, err
		}
		if kid == base64.RawURLEncoding.EncodeToString(thp) {
			var key ecdsa.PublicKey
			if err := webKey.Raw(&key); err != nil {
				return nil, err
			}
			return &key, nil
		}
	}
	return nil, fmt.Errorf("clevis.go/tang: a key with kid '%v' not found in the 'clevis/adv' node", kid)
}
