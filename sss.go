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

// sssEncrypter represents the data samir secret sharing needs to perform encryption
type sssEncrypter struct {
	// Threshold is the number of pins required for decryption
	Threshold int `json:"t"`

	// Pins used to encrypt the key fragments (size must be >= Threshold pins provided)
	Pins map[string][]json.RawMessage `json:"pins"`
}

func parseSssEncrypterConfig(config string) (encrypter, error) {
	var c sssEncrypter
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, err
	}
	return c, nil
}

// Encrypt a bytestream according to the sssEncrypter
func (c sssEncrypter) encrypt(data []byte) ([]byte, error) {
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

	clevis := map[string]interface{}{
		"pin": "sss",
		"sss": sssDecrypter{
			Threshold: c.Threshold,
			Prime:     primeEncoded,
			Jwe:       pinSecrets,
		},
	}
	m, err := json.Marshal(clevis)
	if err != nil {
		return nil, err
	}

	hdrs := jwe.NewHeaders()
	if err := hdrs.Set("clevis", json.RawMessage(m)); err != nil {
		return nil, err
	}

	encKey := extendBytes(coeff[0].Bytes(), primeLength) // we use 0-th coefficient as the encryption key
	return jwe.Encrypt(data, jwa.DIRECT, encKey, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(hdrs))
}

// sssDecrypter represents the data samir secret sharing needs to perform decryption
type sssDecrypter struct {
	Prime     string   `json:"p"`
	Threshold int      `json:"t"`
	Jwe       []string `json:"jwe"`
}

func parseSssDecrypterConfig(config []byte) (decrypter, error) {
	var d sssDecrypter
	if err := json.Unmarshal(config, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (p sssDecrypter) recoverKey(_ *jwe.Message) ([]byte, error) {
	var prime big.Int
	primeBytes, err := base64.RawURLEncoding.DecodeString(p.Prime)
	if err != nil {
		return nil, err
	}
	prime.SetBytes(primeBytes)
	pointLength := len(primeBytes) // this is a length of numbers we use (p, x, y, resulting secret)

	if !prime.ProbablyPrime(64) {
		return nil, fmt.Errorf("parameter 'p' expected to be a prime number")
	}

	if len(p.Jwe) < p.Threshold {
		return nil, fmt.Errorf("number of points %v is smaller than threshold %v", len(p.Jwe), p.Threshold)
	}

	points := make([]point, 0, p.Threshold)
	for i, j := range p.Jwe {
		pointData, err := Decrypt([]byte(j))
		if err != nil {
			fmt.Println(err)
			continue
		}
		if len(pointData) != 2*pointLength {
			return nil, fmt.Errorf("decoded message #%v should have size of two points (x and y). Expected size 2*%v, got %v", i, pointLength, len(pointData))
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
		return nil, fmt.Errorf("expected interpolated data length is %v, got %v", pointLength, len(cek))
	}
	cek = expandBuffer(cek, pointLength)

	return cek, nil
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
