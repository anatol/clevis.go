package clevis

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var tangBinLocation string

func init() {
	// different OS use different tang server binary location
	tangLocations := []string{
		"/usr/lib/",
		"/usr/lib/x86_64-linux-gnu/",
	}

	for _, l := range tangLocations {
		if _, err := os.Stat(l + "tangd"); err == nil {
			tangBinLocation = l
			break
		}
	}
}

func checkDecryptTang(t *testing.T, h crypto.Hash) {
	// start Tang server
	s, err := NewTangServer(t)
	require.NoError(t, err)
	defer s.Stop()

	const inputText = "some plaintext"

	// encrypt a text using 'clevis-encrypt-tang' like this:
	// clevis-encrypt-tang '{"url":"http://localhost", "thp":"1GDW0VlDv95DwPIm5EOqZVZCMeo"}' <<< "hello"
	config, err := s.TangConfig(h)
	require.NoError(t, err)
	encryptCmd := exec.Command("clevis-encrypt-tang", config)
	encryptCmd.Stdin = strings.NewReader(inputText)
	var encryptedData bytes.Buffer
	encryptCmd.Stdout = &encryptedData
	if testing.Verbose() {
		encryptCmd.Stderr = os.Stderr
	}
	require.NoError(t, encryptCmd.Run())

	compactForm := encryptedData.Bytes()
	jsonForm, err := convertToJSONForm(compactForm)
	require.NoError(t, err)

	// decrypt this text using our implementation
	plaintext1, err := Decrypt(compactForm)
	require.NoError(t, err)
	require.Equal(t, inputText, string(plaintext1), "decryption failed")

	plaintext2, err := Decrypt(jsonForm)
	require.NoError(t, err)
	require.Equal(t, inputText, string(plaintext2), "decryption failed")
}

func TestDecryptTangSHA1(t *testing.T) {
	checkDecryptTang(t, crypto.SHA1)
}

func TestDecryptTangSHA256(t *testing.T) {
	checkDecryptTang(t, crypto.SHA256)
}

func checkEncryptTang(t *testing.T, h crypto.Hash) {
	// start Tang server
	s, err := NewTangServer(t)
	require.NoError(t, err)
	defer s.Stop()

	const inputText = "some plaintext"

	// encrypt a text using 'clevis-encrypt-tang' like this:
	// clevis-encrypt-tang '{"url":"http://localhost", "thp":"1GDW0VlDv95DwPIm5EOqZVZCMeo"}' <<< "hello"
	config, err := s.TangConfig(h)
	require.NoError(t, err)

	// decrypt this text using our implementation
	encrypted, err := EncryptTang([]byte(inputText), config)
	require.NoError(t, err)

	decrypted, err := Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, inputText, string(decrypted), "decryption failed")

	decryptCmd := exec.Command("clevis-decrypt-tang")
	decryptCmd.Stdin = bytes.NewReader(encrypted)
	var decryptedData bytes.Buffer
	decryptCmd.Stdout = &decryptedData
	if testing.Verbose() {
		decryptCmd.Stderr = os.Stderr
	}
	require.NoError(t, decryptCmd.Run())
	require.Equal(t, inputText, decryptedData.String(), "decryption failed")
}

func TestEncryptTangSHA256(t *testing.T) {
	checkEncryptTang(t, crypto.SHA256)
}

type TangServer struct {
	keysDir  string
	listener net.Listener
	quit     chan interface{}
	port     int
}

func NewTangServer(t *testing.T) (*TangServer, error) {
	// generate server keys
	keysDir := t.TempDir()
	err := exec.Command(tangBinLocation+"tangd-keygen", keysDir, "sign", "exchange").Run()
	if err != nil {
		return nil, err
	}

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	s := &TangServer{
		keysDir:  keysDir,
		listener: l,
		port:     l.Addr().(*net.TCPAddr).Port,
		quit:     make(chan interface{}),
	}
	go s.serve()
	return s, nil
}

func (s *TangServer) Stop() {
	close(s.quit)
	_ = s.listener.Close()
}

func (s *TangServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Println("accept error", err)
			}
		} else {
			s.handleConection(conn)
			if err := conn.Close(); err != nil {
				log.Print(err)
			}
		}
	}
}

func (s *TangServer) handleConection(conn net.Conn) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Println("read error", err)
		return
	}
	if n == 0 {
		return
	}

	tangCmd := exec.Command(tangBinLocation+"tangd", s.keysDir)
	tangCmd.Stdin = bytes.NewReader(buf[:n])
	tangCmd.Stdout = conn
	if testing.Verbose() {
		tangCmd.Stderr = os.Stderr
	}
	if err := tangCmd.Run(); err != nil {
		log.Println(err)
	}
}

// hash algorithm names for 'jose jwk thp'
var algos = map[crypto.Hash]string{
	crypto.SHA1:   "S1",
	crypto.SHA256: "S256",
}

func (s *TangServer) thumbprint(h crypto.Hash) (string, error) {
	algo, ok := algos[h]
	if !ok {
		return "", fmt.Errorf("do not know how to calculate thumbprint for hash %s", h.String())
	}

	thpCmd := exec.Command("jose", "jwk", "thp", "-a", algo, "-i", s.keysDir+"/sign.jwk")
	var thpOut bytes.Buffer
	thpCmd.Stdout = &thpOut
	if testing.Verbose() {
		thpCmd.Stderr = os.Stderr
	}
	if err := thpCmd.Run(); err != nil {
		return "", err
	}

	return thpOut.String(), nil
}

func (s *TangServer) TangConfig(h crypto.Hash) (string, error) {
	thp, err := s.thumbprint(h)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`{"url":"http://localhost:%d", "thp":"%s"}`, s.port, thp), nil
}

func TestTangToConfig(t *testing.T) {
	var tests = []struct {
		pin      TangPin
		expected TangConfig
	}{{
		pin:      TangPin{},
		expected: TangConfig{},
	}, {
		pin: TangPin{
			Advertisement: json.RawMessage(`{"keys":[{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"AEFldixpd6xWI1rPigk_i_fW_9SLXh3q3h_CbmRIJ2vmnneWnfylvg37q9_BeSxhLpTQkq580tP-7QiOoNem4ubg","y":"AD8MroFIWQI4nm1rVKOb0ImO0Y7EzPt1HTQfZxagv2IoMez8H_vV7Ra9fU7lJhoe3v-Th6x3-4540FodeIxxiphn"},{"alg":"ES512","crv":"P-521","key_ops":["verify"],"kty":"EC","x":"AFZApUzXzvjVJCZQX1De3LUudI7fiWZcZS3t4F2yrxn0tItCYIZrfygPiCZfV1hVKa3WuH2YMrISZUPrSgi_RN2d","y":"ASEyw-_9xcwNBnvpT7thmAF5qHv9-UPYf38AC7y5QBVejQH_DO1xpKzlTbrHCz0jrMeEir8TyW5ywZIYnqGzPBpn"}]}`),
			URL:           "http://192.168.4.100:7500",
		},
		expected: TangConfig{
			Thumbprint: "Bp8XjITceWSN_7XFfW7WfJDTomE",
			URL:        "http://192.168.4.100:7500",
		},
	}}

	for _, test := range tests {
		c, err := test.pin.toConfig()

		require.NoError(t, err)
		require.Equal(t, test.expected, c)
	}
}

func hexString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestConcatKDF(t *testing.T) {
	require.Equal(t, concatKDF(sha256.New(), []byte("input"), nil, 48), hexString("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955"))
	require.Equal(t, concatKDF(sha256.New(), []byte("input"), nil, 64), hexString("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955f3467fd6672cce1024c5b1effccc0f61"))

	// https://tools.ietf.org/html/rfc7518#appendix-C
	require.Equal(t, concatKDF(sha256.New(), hexString("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4"), hexString("000000074131323847434d00000005416c69636500000003426f6200000080"), 16), hexString("56aa8deaf8236d205c2228cd71a7101a"))
}
