package clevis

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

const remoteDefaultPort = 8609
const defaultThpAlgo = crypto.SHA256

// remoteEncrypter represents the data needed to perform remote tang-based encryption
type remoteEncrypter struct {
	// A trusted advertisement (config JSON or a filename containing JSON)
	Advertisement *json.RawMessage `json:"adv,omitempty"`

	// Port to listen for incoming requests, if not set then 8609 used
	Port int `json:"port"`

	// The thumbprint of a trusted signing key
	Thumbprint string `json:"thp,omitempty"`
}

func parseRemoteEncrypterConfig(config string) (encrypter, error) {
	var c remoteEncrypter
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, err
	}
	if c.Port == 0 {
		c.Port = remoteDefaultPort
	}
	return c, nil
}

// Encrypt encrypts a bytestream for "remote" pin
func (c remoteEncrypter) encrypt(data []byte) ([]byte, error) {
	var path string
	var msgContent []byte

	thumbprint := c.Thumbprint
	if c.Advertisement == nil {
		return nil, fmt.Errorf("no advertisement specified")
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
		"pin": "remote",
		"remote": remoteDecrypter{
			Port:          c.Port,
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

// remoteDecrypter represents the data tang needs to perform decryption
type remoteDecrypter struct {
	Advertisement json.RawMessage `json:"adv"`
	Port          int             `json:"port"`
}

func parseRemoteDecrypterConfig(config []byte) (decrypter, error) {
	var d remoteDecrypter
	if err := json.Unmarshal(config, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (p remoteDecrypter) recoverKey(msg *jwe.Message) ([]byte, error) {
	if p.Advertisement == nil {
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.tang.adv'")
	}

	advertizedKeys, err := jwk.Parse(p.Advertisement)
	if err != nil {
		return nil, err
	}

	headers := msg.ProtectedHeaders()

	receivedKey, err := performEcmrExhangeReverse(p.Port, advertizedKeys, headers.KeyID(), headers.EphemeralPublicKey())
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

func performEcmrExhangeReverse(port int, advertizedKeys jwk.Set, serverKeyID string, e jwk.Key) (*ecdsa.PublicKey, error) {
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

	respKey, err := waitForTangServerRequest(port, advertizedKeys, serverKeyID, xfrKey)
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

func waitForTangServerRequest(port int, advertizedKeys jwk.Set, serverKeyID string, key *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
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

	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return nil, err
		}

		// TODO: add concurrent break here and process each client with a goroutine to avoid blocking each other
		resp, err := handleRequest(conn, advertizedKeys, serverKeyID, reqData)
		if err != nil {
			fmt.Println(err)
			continue
		}

		return resp, nil
	}
}

func handleRequest(conn net.Conn, advertizedKeys jwk.Set, serverKeyID string, reqKey []byte) (*ecdsa.PublicKey, error) {
	defer conn.Close()

	buff := bufio.NewReader(conn)
	msgContent, _, err := buff.ReadLine()
	if err != nil {
		return nil, err
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

	// TODO: find intersection of verifyKeys and advertizedKeys that we have in the pin. The intersection should be non-empty.
	var intersects bool
	for _, i := range filterKeys(advertizedKeys, jwk.KeyOpVerify) {
		for _, j := range verifyKeys {
			if i.KeyID() == j.KeyID() { // ???
				intersects = true
			}
		}
	}
	if !intersects {
		return nil, fmt.Errorf("clients advertisement does not intersect one stored in pin")
	}

	deriveKeys := filterKeys(keys, jwk.KeyOpDeriveKey)
	k, err := findByThumbprint(deriveKeys, serverKeyID)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, fmt.Errorf("the client does not contain derive key with id %s", serverKeyID)
	}

	req := serverKeyID + "\n" + string(reqKey) + "\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	respData, _, err := buff.ReadLine()
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
