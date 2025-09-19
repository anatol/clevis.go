package clevis

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var defaultSymScheme = &tpm2.SymScheme{
	Alg:     tpm2.AlgAES,
	KeyBits: 128,
	Mode:    tpm2.AlgCFB,
}

var defaultRSAParams = &tpm2.RSAParams{
	Symmetric: defaultSymScheme,
	KeyBits:   2048,
}

var defaultECCParams = &tpm2.ECCParams{
	Symmetric: defaultSymScheme,
	CurveID:   tpm2.CurveNISTP256,
}

// tpm2Encrypter represents the data tpm2 needs to perform encryption
type tpm2Encrypter struct {
	Hash      string      `json:"hash,omitempty"`       // Hash algorithm used in the computation of the object name (default: sha256)
	Key       string      `json:"key,omitempty"`        // Algorithm type for the generated key (default: ecc)
	PcrBank   string      `json:"pcr_bank,omitempty"`   // PCR algorithm bank to use for policy (default: sha1)
	PcrIds    interface{} `json:"pcr_ids,omitempty"`    // PCR list used for policy. If not present, no policy is used
	PcrDigest string      `json:"pcr_digest,omitempty"` // Binary PCR hashes encoded in base64. If not present, the hash values are looked up
}

func parseTpm2EncrypterConfig(config string) (encrypter, error) {
	var c tpm2Encrypter
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, err
	}

	var err error
	c.PcrIds, err = parsePcrIds(c.PcrIds) // normalize pcrs array
	if err != nil {
		return nil, err
	}

	return c, nil
}

// encrypt a bytestream according to the tpm2Encrypter
func (c tpm2Encrypter) encrypt(data []byte) ([]byte, error) {
	dev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	if c.Hash == "" {
		c.Hash = "sha256"
	}
	if c.Key == "" {
		c.Key = "ecc"
	}
	if c.PcrBank == "" {
		c.PcrBank = "sha1"
	}

	hashAlgo := getAlgorithm(c.Hash)
	if hashAlgo.IsNull() {
		return nil, fmt.Errorf("unknown hash algo %v", c.Hash)
	}

	keyAlgo := getAlgorithm(c.Key)
	if keyAlgo.IsNull() {
		return nil, fmt.Errorf("unknown key algo %v", c.Key)
	}

	srkTemplate := tpm2.Public{
		Type:          keyAlgo,
		NameAlg:       hashAlgo,
		Attributes:    tpm2.FlagStorageDefault,
		AuthPolicy:    nil,
		ECCParameters: defaultECCParams,
		RSAParameters: defaultRSAParams,
	}

	srkHandle, _, err := tpm2.CreatePrimary(dev, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("can't create primary key: %v", err)
	}
	defer tpm2.FlushContext(dev, srkHandle)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	encKey, err := jwk.Import(key)
	if err != nil {
		return nil, err
	}
	if err := encKey.Set(jwk.AlgorithmKey, jwa.A256GCM()); err != nil {
		return nil, err
	}
	if err := encKey.Set(jwk.KeyTypeKey, jwa.OctetSeq()); err != nil {
		return nil, err
	}
	if err := encKey.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpEncrypt, jwk.KeyOpDecrypt}); err != nil {
		return nil, err
	}
	// {"alg":"A256GCM","k":"RovvC-jLkhqKedLgAPW14-qU729RY7sclBbRB238u8c","key_ops":["encrypt","decrypt"],"kty":"oct"}
	toSeal, err := json.Marshal(encKey)
	if err != nil {
		return nil, err
	}

	var policy []byte
	pcrs, err := parsePcrIds(c.PcrIds)
	if err != nil {
		return nil, err
	}
	if len(pcrs) != 0 {
		var expectedDigest []byte
		if c.PcrDigest != "" {
			expectedDigest, err = base64.RawURLEncoding.DecodeString(c.PcrDigest)
			if err != nil {
				return nil, err
			}
		}

		pcrAlgo := getAlgorithm(c.PcrBank)
		if pcrAlgo.IsNull() {
			return nil, fmt.Errorf("unknown hash algo for pcr: %v", pcrAlgo)
		}

		var sessHandle tpmutil.Handle
		sessHandle, policy, err = policyPCRSession(dev, pcrs, pcrAlgo, expectedDigest)
		if err != nil {
			return nil, err
		}
		defer tpm2.FlushContext(dev, sessHandle)
	}

	inPublic := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSealDefault | tpm2.FlagUserWithAuth, // clevis uses fixedtpm|fixedparent|noda|adminwithpolicy|userwithauth, do we need these flags here?,
		AuthPolicy: policy,
	}
	privateArea, publicArea, _, _, _, err := tpm2.CreateKeyWithSensitive(dev, srkHandle, tpm2.PCRSelection{}, "", "", inPublic, toSeal)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 2)
	// TPM2B structures are big-endian
	binary.BigEndian.PutUint16(buff, uint16(len(privateArea)))
	privateArea = append(buff, privateArea...)
	binary.BigEndian.PutUint16(buff, uint16(len(publicArea)))
	publicArea = append(buff, publicArea...)

	hdrs := jwe.NewHeaders()
	if err := hdrs.Set(jwe.AlgorithmKey, jwa.DIRECT()); err != nil {
		return nil, err
	}
	if err := hdrs.Set(jwe.ContentEncryptionKey, jwa.A256GCM()); err != nil {
		return nil, err
	}

	clevis := map[string]interface{}{
		"pin": "tpm2",
		"tpm2": tpm2Decrypter{
			Key:     c.Key,
			Hash:    c.Hash,
			JwkPub:  base64.RawURLEncoding.EncodeToString(publicArea),
			JwkPriv: base64.RawURLEncoding.EncodeToString(privateArea),
			PcrIds:  c.PcrIds,
			PcrBank: c.PcrBank,
		},
	}
	m, err := json.Marshal(clevis)
	if err != nil {
		return nil, err
	}
	if err := hdrs.Set("clevis", json.RawMessage(m)); err != nil {
		return nil, err
	}

	return jwe.Encrypt(data, jwe.WithKey(jwa.DIRECT(), key), jwe.WithContentEncryption(jwa.A256GCM()), jwe.WithCompress(jwa.NoCompress()), jwe.WithProtectedHeaders(hdrs))
}

var useSWEmulatorPort = -1

func openTPM() (io.ReadWriteCloser, error) {
	if useSWEmulatorPort != -1 {
		dev, err := net.Dial("tcp", fmt.Sprintf(":%d", useSWEmulatorPort))
		if err != nil {
			return nil, err
		}

		if _, err := tpm2.GetManufacturer(dev); err != nil {
			return nil, fmt.Errorf("open tcp port %d: device is not a TPM 2.0", useSWEmulatorPort)
		}
		return dev, nil
	}
	return tpm2.OpenTPM("/dev/tpmrm0")
}

// tpm2Decrypter represents the data tpm2 needs to perform decryption
type tpm2Decrypter struct {
	Hash    string      `json:"hash,omitempty"`
	Key     string      `json:"key,omitempty"`
	JwkPub  string      `json:"jwk_pub,omitempty"`
	JwkPriv string      `json:"jwk_priv,omitempty"`
	PcrBank string      `json:"pcr_bank,omitempty"`
	PcrIds  interface{} `json:"pcr_ids,omitempty"`
}

func parseTpm2DecrypterConfig(config []byte) (decrypter, error) {
	var d tpm2Decrypter
	if err := json.Unmarshal(config, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (p tpm2Decrypter) recoverKey(_ *jwe.Message) ([]byte, error) {
	dev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	_, err = tpm2.GetManufacturer(dev)
	if err != nil {
		return nil, fmt.Errorf("open %s: device is not a TPM 2.0", dev)
	}

	// tpm2_createprimary -Q -C "$auth" -g "$hash" -G "$key" -c "$TMP"/primary.context
	hashAlgo := getAlgorithm(p.Hash)
	if hashAlgo.IsNull() {
		return nil, fmt.Errorf("unknown hash algo %v", p.Hash)
	}

	keyAlgo := getAlgorithm(p.Key)
	if keyAlgo.IsNull() {
		return nil, fmt.Errorf("unknown key algo %v", p.Key)
	}

	srkTemplate := tpm2.Public{
		Type:          keyAlgo,
		NameAlg:       hashAlgo,
		Attributes:    tpm2.FlagStorageDefault,
		AuthPolicy:    nil,
		ECCParameters: defaultECCParams,
		RSAParameters: defaultRSAParams,
	}

	srkHandle, _, err := tpm2.CreatePrimary(dev, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("can't create primary key: %v", err)
	}
	defer tpm2.FlushContext(dev, srkHandle)

	// tpm2_load -Q -C "$TMP"/primary.context -u "$TMP"/jwk.pub -r "$TMP"/jwk.priv -c "$TMP"/objectHandle.context
	jwkPrivBlob, err := base64.RawURLEncoding.DecodeString(p.JwkPriv)
	if err != nil {
		return nil, err
	}
	jwkPrivBlob = jwkPrivBlob[2:] // this is marshalled TPM2B_PRIVATE structure, cut 2 bytes from the beginning to get the data

	jwkPubBlob, err := base64.RawURLEncoding.DecodeString(p.JwkPub)
	if err != nil {
		return nil, err
	}
	jwkPubBlob = jwkPubBlob[2:] // this is marshalled TPM2B_PUBLIC structure, cut 2 bytes from the beginning to get the data

	objectHandle, _, err := tpm2.Load(dev, srkHandle, "", jwkPubBlob, jwkPrivBlob)
	if err != nil {
		return nil, fmt.Errorf("unable to load data: %v", err)
	}
	defer tpm2.FlushContext(dev, objectHandle)

	var unsealed []byte

	pcrs, err := parsePcrIds(p.PcrIds)
	if err != nil {
		return nil, err
	}
	if len(pcrs) == 0 {
		unsealed, err = tpm2.Unseal(dev, objectHandle, "")
		if err != nil {
			return nil, err
		}
	} else {
		pcrAlgo := getAlgorithm(p.PcrBank)
		if pcrAlgo.IsNull() {
			return nil, fmt.Errorf("unknown hash algo for pcr: %v", p.PcrBank)
		}

		sessHandle, _, err := policyPCRSession(dev, pcrs, pcrAlgo, nil)
		if err != nil {
			return nil, err
		}
		defer tpm2.FlushContext(dev, sessHandle)

		// Unseal the data
		// tpm2_unseal -c "$TMP"/objectHandle.context -p pcr:sha1:0,1
		unsealed, err = tpm2.UnsealWithSession(dev, sessHandle, objectHandle, "")
		if err != nil {
			return nil, fmt.Errorf("unable to unseal data: %v", err)
		}
	}

	key, err := jwk.ParseKey(unsealed)
	if err != nil {
		return nil, err
	}
	symmKey, ok := key.(jwk.SymmetricKey)
	if !ok {
		return nil, fmt.Errorf("unsealed key expected to be a symmetric key")
	}

	oct, ok := symmKey.Octets()
	if !ok {
		return nil, fmt.Errorf("could not obtain octets from symmetric key")
	}
	return oct, nil
}

// Returns session handle and policy digest.
func policyPCRSession(dev io.ReadWriteCloser, pcrs []int, algo tpm2.Algorithm, expectedDigest []byte) (handle tpmutil.Handle, policy []byte, retErr error) {
	// We hard-code SHA256 as the policy session hash algorithms. Note that this
	// differs from the PCR hash algorithm (which selects the bank of PCRs to use)
	// and the Public area Name algorithm. We also chose this for compatibility with
	// github.com/google/go-tpm/tpm2, as it hardcodes the nameAlg as SHA256 in
	// several places. Two constants are used to avoid repeated conversions.
	const sessionHashAlg = crypto.SHA256
	const sessionHashAlgTpm = tpm2.AlgSHA256

	// This session assumes the bus is trusted, so we:
	// - use nil for tpmkey, encrypted salt, and symmetric
	// - use and all-zeros caller nonce, and ignore the returned nonce
	// As we are creating a plain TPM session, we:
	// - setup a policy session
	// - don't bind the session to any particular key
	sessHandle, _, err := tpm2.StartAuthSession(
		dev,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ make([]byte, sessionHashAlg.Size()),
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ sessionHashAlgTpm)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}

	pcrSelection := tpm2.PCRSelection{
		Hash: algo,
		PCRs: pcrs,
	}

	// An empty expected digest means that digest verification is skipped.
	if err := tpm2.PolicyPCR(dev, sessHandle, expectedDigest, pcrSelection); err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
	}

	policy, err = tpm2.PolicyGetDigest(dev, sessHandle)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}
	return sessHandle, policy, nil
}

func parsePcrIds(pcrList interface{}) ([]int, error) {
	switch pcrList := pcrList.(type) {
	case nil:
		return nil, nil
	case string:
		pcrsSplice := strings.Split(pcrList, ",")
		pcrIds := make([]int, len(pcrsSplice))

		for i, s := range pcrsSplice {
			var err error
			s = strings.TrimSpace(s)
			pcrIds[i], err = strconv.Atoi(s)
			if err != nil {
				return nil, err
			}
		}
		return pcrIds, nil
	case []int:
		return pcrList, nil
	case []interface{}:
		res := make([]int, len(pcrList))
		for i, v := range pcrList {
			switch v := v.(type) {
			case float64:
				res[i] = int(v)
			case int:
				res[i] = v
			case string:
				var err error
				v = strings.TrimSpace(v)
				res[i], err = strconv.Atoi(v)
				if err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("unknown type of element %+v", v)
			}
		}
		return res, nil
	default:
		return nil, fmt.Errorf("unknown pcr_ids type: %+v", pcrList)
	}
}

func getAlgorithm(name string) tpm2.Algorithm {
	switch name {
	case "rsa":
		return tpm2.AlgRSA
	case "sha1":
		return tpm2.AlgSHA1
	case "hmac":
		return tpm2.AlgHMAC
	case "aes":
		return tpm2.AlgAES
	case "xor":
		return tpm2.AlgXOR
	case "sha256":
		return tpm2.AlgSHA256
	case "sha384":
		return tpm2.AlgSHA384
	case "sha512":
		return tpm2.AlgSHA512
	case "null":
		return tpm2.AlgNull
	case "rsassa":
		return tpm2.AlgRSASSA
	case "rsaes":
		return tpm2.AlgRSAES
	case "rsapss":
		return tpm2.AlgRSAPSS
	case "oaep":
		return tpm2.AlgOAEP
	case "ecdsa":
		return tpm2.AlgECDSA
	case "ecdh":
		return tpm2.AlgECDH
	case "ecdaa":
		return tpm2.AlgECDAA
	case "kdf2":
		return tpm2.AlgKDF2
	case "ecc":
		return tpm2.AlgECC
	case "ctr":
		return tpm2.AlgCTR
	case "ofb":
		return tpm2.AlgOFB
	case "cbc":
		return tpm2.AlgCBC
	case "cfb":
		return tpm2.AlgCFB
	case "ecb":
		return tpm2.AlgECB
	default:
		return tpm2.AlgUnknown
	}
}
