package clevis

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
)

// SssPin represents the data samir secret sharing needs to perform decryption
type SssPin struct {
	Prime     string   `json:"p"`
	Threshold int      `json:"t"`
	Jwe       []string `json:"jwe"`
}

// toConfig converts a given SssPin into the corresponding SssConfig which can be used for encryption
func (p SssPin) toConfig() (SssConfig, error) {
	c := SssConfig{
		Threshold: p.Threshold,
		Pins:      make(map[string][]json.RawMessage),
	}
	for _, jwePin := range p.Jwe {
		_, pin, err := Parse([]byte(jwePin))
		if err != nil {
			return c, err
		}
		var cfg interface{}
		switch pin.Pin {
		case "tang":
			cfg, err = pin.Tang.toConfig()
		case "tpm2":
			cfg, err = pin.Tpm2.toConfig()
		case "sss":
			cfg, err = pin.Sss.toConfig()
		case "yubikey":
			cfg, err = pin.Yubikey.toConfig()
		default:
			return c, fmt.Errorf("clevis.go: unknown pin '%v'", pin.Pin)
		}
		if err != nil {
			return c, err
		}
		cfgBytes, err := json.Marshal(cfg)
		if err != nil {
			return c, err
		}
		c.Pins[pin.Pin] = append(c.Pins[pin.Pin], cfgBytes)
	}
	return c, nil
}

func (p SssPin) prepareDecryptionCtx(ctx jwe.DecryptCtx) error {
	var prime big.Int
	primeBytes, err := base64.RawURLEncoding.DecodeString(p.Prime)
	if err != nil {
		return err
	}
	prime.SetBytes(primeBytes)
	pointLength := len(primeBytes) // this is a length of numbers we use (p, x, y, resulting secret)

	if !prime.ProbablyPrime(64) {
		return fmt.Errorf("clevis.go/sss: parameter 'p' expected to be a prime number")
	}

	if len(p.Jwe) < p.Threshold {
		return fmt.Errorf("clevis.go/sss: number of points %v is smaller than threshold %v", len(p.Jwe), p.Threshold)
	}

	points := make([]point, 0, p.Threshold)
	for i, j := range p.Jwe {
		pointData, err := Decrypt([]byte(j))
		if err != nil {
			fmt.Println(err)
			continue
		}
		if len(pointData) != 2*pointLength {
			return fmt.Errorf("clevis.go/sss: decoded message #%v should have size of two points (x and y). Expected size 2*%v, got %v", i, pointLength, len(pointData))
		}

		x := new(big.Int).SetBytes(pointData[:pointLength])
		y := new(big.Int).SetBytes(pointData[pointLength:])

		points = append(points, point{x, y})

		if len(points) == p.Threshold {
			// alright, there is enough points to interpolate the polynomial
			break
		}
	}

	cek := lagrangeInterpolation(&prime, points).Bytes()
	if len(cek) > pointLength {
		return fmt.Errorf("clevis.go/sss: expected interpolated data length is %v, got %v", pointLength, len(cek))
	}
	cek = expandBuffer(cek, pointLength)

	ctx.SetAlgorithm(jwa.DIRECT)
	ctx.SetKey(cek)
	return nil
}

// SssConfig represents the data samir secret sharing needs to perform encryption
type SssConfig struct {
	// Threshold is the number of pins required for decryption
	Threshold int `json:"t"`

	// Pins used to encrypt the key fragments (must be >= Threshold pins provided)
	Pins map[string][]json.RawMessage `json:"pins"`
}

// NewSssConfig parses the given json-format sss config into a SssConfig
func NewSssConfig(config string) (SssConfig, error) {
	var c SssConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return c, err
	}
	return c, nil
}

// EncryptSss encrypts a bytestream according to the json-format sss config
func EncryptSss(data []byte, config string) ([]byte, error) {
	c, err := NewSssConfig(config)
	if err != nil {
		return nil, err
	}
	return c.encrypt(data)
}

// encrypt a bytestream according to the SssConfig
func (c SssConfig) encrypt(data []byte) ([]byte, error) {
	if c.Threshold < 1 {
		return nil, fmt.Errorf("invalid threshold value")
	}

	primeLength := 32
	p, err := rand.Prime(rand.Reader, primeLength*8) // 32 bytes long prime
	if err != nil {
		return nil, err
	}
	if len(p.Bytes()) != primeLength {
		return nil, fmt.Errorf("generated prime is not long enough")
	}

	coeff := make([]*big.Int, c.Threshold)
	for i := 0; i < c.Threshold; i++ {
		n, err := rand.Int(rand.Reader, p)
		if err != nil {
			return nil, err
		}
		coeff[i] = n
	}

	var pinSecrets []string // encrypted pin secrets, what later becomes 'jwe' node
	for name, entries := range c.Pins {
		for _, entry := range entries {
			pinCfg, err := entry.MarshalJSON()
			if err != nil {
				return nil, err
			}

			x, err := rand.Int(rand.Reader, p)
			if err != nil {
				return nil, err
			}

			/* y += coeff[i] * x^i */
			y := big.NewInt(0)
			for i, ci := range coeff {
				z := big.NewInt(0)
				z.Exp(x, big.NewInt(int64(i)), p)
				z.Mul(z, ci)
				z.Mod(z, p)

				y.Add(y, z)
			}
			y.Mod(y, p)

			point := make([]byte, 2*primeLength)
			copy(point, extendBytes(x.Bytes(), primeLength))
			copy(point[primeLength:], extendBytes(y.Bytes(), primeLength))

			secret, err := Encrypt(point, name, string(pinCfg))
			if err != nil {
				return nil, err
			}
			pinSecrets = append(pinSecrets, string(secret))
		}
	}

	primeEncoded := base64.RawURLEncoding.EncodeToString(p.Bytes())

	hdrs := jwe.NewHeaders()
	clevis := Pin{
		Pin: "sss",
		Sss: &SssPin{
			Threshold: c.Threshold,
			Prime:     primeEncoded,
			Jwe:       pinSecrets,
		},
	}
	if err := hdrs.Set("clevis", clevis); err != nil {
		return nil, err
	}

	encKey := extendBytes(coeff[0].Bytes(), primeLength) // we use 0-th coefficient as the encryption key
	return jwe.Encrypt(data, jwa.DIRECT, encKey, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(hdrs))
}

func extendBytes(bytes []byte, length int) []byte {
	inputLen := len(bytes)
	if inputLen == length {
		return bytes
	}
	if inputLen > length {
		panic("received array length is larger than requested")
	}
	padding := make([]byte, length-inputLen)
	return append(padding, bytes...)
}

type point struct {
	x, y *big.Int
}

// https://en.wikipedia.org/wiki/Lagrange_polynomial
// to interpolate a polynomial of degree k we need k+1 points and then perform calculation of
// L(x) = SUM(yi * li(x))
// where li(x) is computed as
// li(x) = MULT( (x-xm)/(xj-xm) )
//
// all calculation are performed in galois field with given prime
//
// The function returns value of interpolated polynomial in point x=0 (i.e. value of the last coefficient) which is the
// secret we are looking for.
func lagrangeInterpolation(prime *big.Int, points []point) *big.Int {
	num := len(points)
	result := big.NewInt(0)

	for j := 0; j < num; j++ {
		basis := big.NewInt(1) // value of Lagrange basis polynomial in point x=0

		for m := 0; m < num; m++ {
			if m == j {
				continue
			}

			t1 := big.NewInt(0)
			t1.Sub(t1, points[m].x)
			t1.Mod(t1, prime)

			t2 := new(big.Int).Set(points[j].x)
			t2.Sub(t2, points[m].x)
			t2.ModInverse(t2, prime)

			basis.Mul(basis, t1)
			basis.Mod(basis, prime)
			basis.Mul(basis, t2)
			basis.Mod(basis, prime)
		}

		basis.Mul(basis, points[j].y)
		basis.Mod(basis, prime)
		result.Add(result, basis)
		result.Mod(result, prime)
	}

	return result
}
