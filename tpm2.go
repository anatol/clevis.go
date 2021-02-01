package clevis

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
)

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
	} else {
		return tpm2.OpenTPM("/dev/tpmrm0")
	}
}

// DecryptTpm2 decrypts a jwe message bound with TPM2 clevis pin
func DecryptTpm2(msg *jwe.Message, clevisNode map[string]interface{}) ([]byte, error) {
	dev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	_, err = tpm2.GetManufacturer(dev)
	if err != nil {
		return nil, fmt.Errorf("open %s: device is not a TPM 2.0", dev)
	}

	tpmNode, ok := clevisNode["tpm2"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("clevis.go/tpm2: cannot parse clevis.tpm2 property")
	}

	// tpm2_createprimary -Q -C "$auth" -g "$hash" -G "$key" -c "$TMP"/primary.context
	hashAlgoName, ok := tpmNode["hash"].(string)
	if !ok {
		return nil, fmt.Errorf("clevis.go/tpm2: cannot parse clevis.tpm2.hash property")
	}
	hashAlgo := getAlgorithm(hashAlgoName)
	if hashAlgo.IsNull() {
		return nil, fmt.Errorf("clevis.go/tpm2: unknown hash algo %v", hashAlgoName)
	}

	keyAlgoName, ok := tpmNode["key"].(string)
	if !ok {
		return nil, fmt.Errorf("clevis.go/tpm2: cannot parse clevis.tpm2.key property")
	}
	keyAlgo := getAlgorithm(keyAlgoName)
	if keyAlgo.IsNull() {
		return nil, fmt.Errorf("clevis.go/tpm2: unknown key algo %v", keyAlgoName)
	}

	srkTemplate := tpm2.Public{
		Type:       keyAlgo,
		NameAlg:    hashAlgo,
		Attributes: tpm2.FlagStorageDefault,
		AuthPolicy: nil,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{ // are these parameters related to content of /etc/tpm2-tss/fapi-profiles/P_ECCP256SHA256.json ?
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
		},
	}

	srkHandle, _, err := tpm2.CreatePrimary(dev, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("clevis.go/tpm2: can't create primary key: %v", err)
	}
	defer tpm2.FlushContext(dev, srkHandle)

	// tpm2_load -Q -C "$TMP"/primary.context -u "$TMP"/jwk.pub -r "$TMP"/jwk.priv -c "$TMP"/objectHandle.context
	jwkPriv, ok := tpmNode["jwk_priv"].(string)
	if !ok {
		return nil, fmt.Errorf("clevis.go/tpm2: cannot parse clevis.tpm2.jwk_priv property")
	}
	jwkPrivBlob, err := base64.RawURLEncoding.DecodeString(jwkPriv)
	if err != nil {
		return nil, err
	}
	jwkPrivBlob = jwkPrivBlob[2:] // this is marshalled TPM2B_PRIVATE structure, cut 2 bytes from the beginning to get the data

	jwkPub, ok := tpmNode["jwk_pub"].(string)
	if !ok {
		return nil, fmt.Errorf("clevis.go/tpm2: cannot parse clevis.tpm2.jwk_pub property")
	}
	jwkPubBlob, err := base64.RawURLEncoding.DecodeString(jwkPub)
	if err != nil {
		return nil, err
	}
	jwkPubBlob = jwkPubBlob[2:] // this is marshalled TPM2B_PUBLIC structure, cut 2 bytes from the beginning to get the data

	objectHandle, _, err := tpm2.Load(dev, srkHandle, "", jwkPubBlob, jwkPrivBlob)
	if err != nil {
		return nil, fmt.Errorf("clevis.go/tpm2: unable to load data: %v", err)
	}
	defer tpm2.FlushContext(dev, objectHandle)

	// tpm2_unseal -c "$TMP"/objectHandle.context -p pcr:sha1:0,1
	pcrSelection, err := extractPcrSelection(tpmNode)
	if err != nil {
		return nil, err
	}

	var unsealed []byte

	if pcrSelection == nil {
		unsealed, err = tpm2.Unseal(dev, objectHandle, "")
		if err != nil {
			return nil, err
		}
	} else {
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
			return nil, fmt.Errorf("unable to start session: %v", err)
		}
		defer tpm2.FlushContext(dev, sessHandle)

		// An empty expected digest means that digest verification is skipped.
		if err := tpm2.PolicyPCR(dev, sessHandle, nil /*expectedDigest*/, *pcrSelection); err != nil {
			return nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
		}

		// Unseal the data
		unsealed, err = tpm2.UnsealWithSession(dev, sessHandle, objectHandle, "")
		if err != nil {
			return nil, fmt.Errorf("unable to unseal data: %v", err)
		}
	}

	keys, err := jwk.Parse(unsealed)
	if err != nil {
		return nil, err
	}
	if keys.Len() != 1 {
		return nil, fmt.Errorf("clevis.go/tpm2: expected to have 1 key in unsealed data, got %v", keys.Len())
	}
	key, ok := keys.Get(0)
	if !ok {
		return nil, fmt.Errorf("clevis.go/tpm2: unable to get a key with index 0")
	}
	symmKey, ok := key.(jwk.SymmetricKey)
	if !ok {
		return nil, fmt.Errorf("clevis.go/tpm2: unsealed key expected to be a symmetric key")
	}
	return msg.Decrypt(jwa.DIRECT, symmKey.Octets())
}

func extractPcrSelection(tpmNode map[string]interface{}) (*tpm2.PCRSelection, error) {
	if _, hasPcr := tpmNode["pcr_ids"]; hasPcr {
		pcrBank, ok := tpmNode["pcr_bank"].(string)
		if !ok {
			return nil, fmt.Errorf("clevis.go/tpm2: cannot parse clevis.tpm2.pcr_bank property")
		}
		pcrAlgo := getAlgorithm(pcrBank)
		if pcrAlgo.IsNull() {
			return nil, fmt.Errorf("clevis.go/tpm2: unknown hash algo for pcr: %v", pcrAlgo)
		}

		pcrIdsNode, ok := tpmNode["pcr_ids"].(string)
		if !ok {
			return nil, fmt.Errorf("clevis.go/tpm2: cannot parse clevis.tpm2.pcr_ids property")
		}
		pcrsSplice := strings.Split(pcrIdsNode, ",")
		pcrIds := make([]int, len(pcrsSplice))

		for i, s := range pcrsSplice {
			var err error
			pcrIds[i], err = strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("clevis.go/tpm2: invalid integers in clevis.tpm2.pcr_ids property: %v", pcrIdsNode)
			}
		}

		return &tpm2.PCRSelection{
			Hash: pcrAlgo,
			PCRs: pcrIds,
		}, nil
	}
	return nil, nil
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
