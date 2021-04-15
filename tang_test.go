package clevis

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"io/ioutil"
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

func TestDecryptTang(t *testing.T) {
	// start Tang server
	s, err := NewTangServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	const inputText = "some plaintext"

	// encrypt a text using 'clevis-encrypt-tang' like this:
	// clevis-encrypt-tang '{"url":"http://localhost", "thp":"1GDW0VlDv95DwPIm5EOqZVZCMeo"}' <<< "hello"
	encryptCmd := exec.Command("clevis-encrypt-tang", s.TangConfig())
	encryptCmd.Stdin = strings.NewReader(inputText)
	var encryptedData bytes.Buffer
	encryptCmd.Stdout = &encryptedData
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

// hash algorithm names for'jose jwk thp'
var algos = map[crypto.Hash]string{
	crypto.SHA1:   "S1",
	crypto.SHA256: "S256",
}

func signingKeyThumbprint(dir string, hash crypto.Hash) (string, error) {
	readDir, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}

	for _, f := range readDir {
		marker := `"key_ops":["sign","verify"]`
		content, err := ioutil.ReadFile(dir + "/" + f.Name())
		if err != nil {
			return "", err
		}
		if !bytes.Contains(content, []byte(marker)) {
			continue
		}

		algo, ok := algos[hash]
		if !ok {
			return "", fmt.Errorf("do not know how to calculate thumbprint for hash %s", hash.String())
		}

		thpCmd := exec.Command("jose", "jwk", "thp", "-a", algo, "-i", dir+"/"+f.Name())
		var thpOut bytes.Buffer
		thpCmd.Stdout = &thpOut
		if err := thpCmd.Run(); err != nil {
			return "", err
		}

		return thpOut.String(), nil
	}

	return "", fmt.Errorf("cannot find a key with 'sign' op")
}

type TangServer struct {
	keysDir    string
	thumbprint string // default key thumbprint
	listener   net.Listener
	quit       chan interface{}
	port       int
}

func NewTangServer(t *testing.T) (*TangServer, error) {
	// generate server keys
	keysDir := t.TempDir()
	err := exec.Command(tangBinLocation+"tangd-keygen", keysDir).Run()
	if err != nil {
		return nil, err
	}

	// calculate thumbprint of the generated key using 'jose jwk thp -i $DBDIR/$SIG.jwk'
	var thumbprint string
	thumbprint, err = signingKeyThumbprint(keysDir, crypto.SHA1)
	if err != nil {
		return nil, err
	}

	var l net.Listener
	l, err = net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	s := &TangServer{
		keysDir:    keysDir,
		thumbprint: thumbprint,
		listener:   l,
		port:       l.Addr().(*net.TCPAddr).Port,
		quit:       make(chan interface{}),
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
	for {
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
		if testing.Verbose() {
			tangCmd.Stderr = os.Stderr
		}
		tangCmd.Stdout = conn
		if err := tangCmd.Run(); err != nil {
			log.Println(err)
		}
	}
}

func (s *TangServer) TangConfig() string {
	return fmt.Sprintf(`{"url":"http://localhost:%d", "thp":"%s"}`, s.port, s.thumbprint)
}
