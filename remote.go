package clevis

import (
	"bufio"
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const (
	remoteDefaultPort = 8609
	defaultThpAlgo    = crypto.SHA256
)

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

	clevis := map[string]interface{}{
		"pin": "remote",
		"remote": remoteDecrypter{
			Port:          c.Port,
			Advertisement: msg.Payload(),
		},
	}

	return encryptWithTangProtocol(data, msgContent, msg, c.Thumbprint, clevis)
}

// remoteDecrypter represents the data remote needs to perform decryption
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
		return nil, fmt.Errorf("cannot parse provided token, node 'clevis.remote.adv'")
	}

	exchangeWithTang := func(serverKeyID string, advertizedKeys jwk.Set, reqData []byte) ([]byte, error) {
		l, err := net.Listen("tcp", ":"+strconv.Itoa(p.Port))
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
			resp, err := handleRemoteRequest(conn, advertizedKeys, serverKeyID, reqData)
			if err != nil {
				fmt.Println(err)
				continue
			}

			return resp, nil
		}
	}
	return recoverKeyWithTangProtocol(msg, p.Advertisement, exchangeWithTang)
}

func handleRemoteRequest(conn net.Conn, storedAdvertizedKeys jwk.Set, serverKeyID string, reqData []byte) ([]byte, error) {
	defer conn.Close()

	buff := bufio.NewReader(conn)
	clientAdv, _, err := buff.ReadLine()
	if err != nil {
		return nil, err
	}

	if err := verifyRemoteKeys(clientAdv, storedAdvertizedKeys, serverKeyID); err != nil {
		return nil, err
	}

	req := serverKeyID + "\n" + string(reqData) + "\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	respData, _, err := buff.ReadLine()
	return respData, err
}

// the function checks that advertisement provided by the connected client is valid.
func verifyRemoteKeys(clientAdv []byte, storedAdvertizedKeys jwk.Set, serverKeyID string) error {
	msg, err := jws.Parse(clientAdv)
	if err != nil {
		return err
	}

	clientAdvertizedKeys, err := jwk.Parse(msg.Payload())
	if err != nil {
		return err
	}

	clientVerifyKeys := filterKeys(clientAdvertizedKeys, jwk.KeyOpVerify)
	if clientVerifyKeys == nil {
		return fmt.Errorf("advertisement is missing signatures")
	}

	for _, key := range clientVerifyKeys {
		keyalg, ok := key.Algorithm()
		if !ok {
			return fmt.Errorf("key does not have an algorithm")
		}

		alg, ok := keyalg.(jwa.SignatureAlgorithm)
		if !ok {
			return fmt.Errorf("algorithm %s is not a signature algorithm", keyalg)
		}
		if _, err := jws.Verify(clientAdv, jws.WithKey(alg, key)); err != nil {
			return err
		}
	}

	storedVerifyKeys := filterKeys(storedAdvertizedKeys, jwk.KeyOpVerify)
	if !keysIntersect(clientVerifyKeys, storedVerifyKeys) {
		return fmt.Errorf("client advertisement does not intersect keys stored in pin")
	}

	clientDeriveKeys := filterKeys(clientAdvertizedKeys, jwk.KeyOpDeriveKey)
	k, err := findByThumbprint(clientDeriveKeys, serverKeyID)
	if err != nil {
		return err
	}
	if k == nil {
		return fmt.Errorf("the client does not contain derive key with id %s", serverKeyID)
	}
	return nil
}
