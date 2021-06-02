package clevis

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
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
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	const inputText = "some plaintext"

	// encrypt a text using 'clevis-encrypt-tang' like this:
	// clevis-encrypt-tang '{"url":"http://localhost", "thp":"1GDW0VlDv95DwPIm5EOqZVZCMeo"}' <<< "hello"
	config, err := s.TangConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	encryptCmd := exec.Command("clevis-encrypt-tang", config)
	encryptCmd.Stdin = strings.NewReader(inputText)
	var encryptedData bytes.Buffer
	encryptCmd.Stdout = &encryptedData
	if testing.Verbose() {
		encryptCmd.Stderr = os.Stderr
	}
	if err := encryptCmd.Run(); err != nil {
		t.Fatal(err)
	}

	compactForm := encryptedData.Bytes()
	jsonForm, err := convertToJsonForm(compactForm)
	if err != nil {
		t.Fatal(err)
	}

	// decrypt this text using our implementation
	plaintext1, err := Decrypt(compactForm)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext1) != inputText {
		t.Fatalf("tang decryption failed: expected '%s', got '%s'", inputText, string(plaintext1))
	}

	plaintext2, err := Decrypt(jsonForm)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext2) != inputText {
		t.Fatalf("tang decryption failed: expected '%s', got '%s'", inputText, string(plaintext2))
	}
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
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	const inputText = "some plaintext"

	// encrypt a text using 'clevis-encrypt-tang' like this:
	// clevis-encrypt-tang '{"url":"http://localhost", "thp":"1GDW0VlDv95DwPIm5EOqZVZCMeo"}' <<< "hello"
	config, err := s.TangConfig(h)
	if err != nil {
		t.Fatal(err)
	}

	// decrypt this text using our implementation
	encrypted, err := EncryptTang([]byte(inputText), config)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt(encrypted)
	if string(decrypted) != inputText {
		t.Fatalf("decryption decryption failed: expected '%s', got '%s'", inputText, string(decrypted))
	}

	decryptCmd := exec.Command("clevis-decrypt-tang")
	decryptCmd.Stdin = bytes.NewReader(encrypted)
	var decryptedData bytes.Buffer
	decryptCmd.Stdout = &decryptedData
	if testing.Verbose() {
		decryptCmd.Stderr = os.Stderr
	}
	if err := decryptCmd.Run(); err != nil {
		t.Fatal(err)
	}

	if decryptedData.String() != inputText {
		t.Fatalf("decryption decryption failed: expected '%s', got '%s'", inputText, string(encrypted))
	}
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
