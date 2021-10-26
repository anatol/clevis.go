package clevis

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func checkDecryption(t *testing.T, tpmPathEnvvar string) {
	inputText := "hi"

	clevisConfigs := []string{
		`{}`,
		`{"pcr_bank":"sha1","pcr_ids":"0,1"}`,
		`{"key":"rsa"}`,
	}

	for _, c := range clevisConfigs {
		var outbuf bytes.Buffer
		cmd := exec.Command("./clevis-encrypt-tpm2", c)
		if tpmPathEnvvar != "" {
			cmd.Env = append(os.Environ(), tpmPathEnvvar)
		}
		cmd.Stdin = strings.NewReader(inputText)
		cmd.Stdout = &outbuf
		cmd.Stderr = os.Stderr

		require.NoError(t, cmd.Run())

		compactForm := outbuf.Bytes()
		jsonForm, err := convertToJSONForm(compactForm)
		require.NoError(t, err)

		// decrypt compact form using our implementation
		plaintext1, err := Decrypt(compactForm)
		require.NoError(t, err)
		require.Equal(t, inputText, string(plaintext1), "compact decryption failed")

		// decrypt json form using our implementation
		plaintext2, err := Decrypt(jsonForm)
		require.NoError(t, err)
		require.Equal(t, inputText, string(plaintext2), "json decryption failed")
	}
}

// convertToJSONForm converts jwx message from a compact form to JSON
func convertToJSONForm(compactData []byte) ([]byte, error) {
	var outbuf bytes.Buffer
	// jose jwe fmt -i- -c <<< $data
	cmd := exec.Command("jose", "jwe", "fmt", "-i-")
	cmd.Stdin = bytes.NewReader(compactData)
	cmd.Stdout = &outbuf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return outbuf.Bytes(), nil
}

func TestDecryptTpm2Hardware(t *testing.T) {
	matches, err := filepath.Glob("/sys/kernel/security/tpm*")
	require.NoError(t, err)

	if len(matches) == 0 {
		t.Skip("There is no hardware TPM chip at this system")
	}

	useSWEmulatorPort = -1
	checkDecryption(t, "") // by default tpm-tools will use /dev/tpmrmX
}

func TestDecryptTpm2Emulator(t *testing.T) {
	tpm, err := NewTpmEmulator(t.TempDir())
	require.NoError(t, err)
	defer tpm.Stop()

	useSWEmulatorPort = tpm.port
	checkDecryption(t, tpm.TctiEnvvar())
}

func checkEncryption(t *testing.T, tpmPathEnvvar string) {
	inputText := "hi"

	clevisConfigs := []string{
		`{}`,
		`{"pcr_bank":"sha1","pcr_ids":"0,1"}`,
		`{"key":"rsa"}`,
	}

	for _, c := range clevisConfigs {
		// decrypt compact form using our implementation
		encrypted, err := EncryptTpm2([]byte(inputText), c)
		require.NoError(t, err)

		decrypted, err := Decrypt(encrypted)
		require.NoError(t, err)
		require.Equal(t, inputText, string(decrypted), "decryption failed")

		var outbuf bytes.Buffer
		cmd := exec.Command("./clevis-decrypt-tpm2")
		if tpmPathEnvvar != "" {
			cmd.Env = append(os.Environ(), tpmPathEnvvar)
		}
		cmd.Stdin = bytes.NewReader(encrypted)
		cmd.Stdout = &outbuf
		cmd.Stderr = os.Stderr

		require.NoError(t, cmd.Run())

		require.Equal(t, inputText, outbuf.String(), "decryption failed")
	}
}

func TestEncryptTpm2Hardware(t *testing.T) {
	matches, err := filepath.Glob("/sys/kernel/security/tpm*")
	require.NoError(t, err)

	if len(matches) == 0 {
		t.Skip("There is no hardware TPM chip at this system")
	}

	useSWEmulatorPort = -1
	checkEncryption(t, "") // by default tpm-tools will use /dev/tpmrmX
}

func TestEncryptTpm2Emulator(t *testing.T) {
	tpm, err := NewTpmEmulator(t.TempDir())
	require.NoError(t, err)
	defer tpm.Stop()

	useSWEmulatorPort = tpm.port
	checkEncryption(t, tpm.TctiEnvvar())
}

type TpmEmulator struct {
	port        int
	controlPort int
	stateDir    string
	cmd         *exec.Cmd
}

func configDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}

	return os.Getenv("HOME") + "/.config"
}

func NewTpmEmulator(stateDir string) (*TpmEmulator, error) {
	if _, err := os.Stat(configDir() + "/swtpm_setup.conf"); os.IsNotExist(err) {
		if err := exec.Command("/usr/share/swtpm/swtpm-create-user-config-files").Run(); err != nil {
			return nil, err
		}
	}

	setupCmd := exec.Command("swtpm_setup", "--tpm-state", stateDir, "--tpm2", "--ecc", "--create-ek-cert", "--create-platform-cert", "--lock-nvram")
	if err := setupCmd.Run(); err != nil {
		return nil, err
	}

	serverCmd := exec.Command("swtpm", "socket", "--tpmstate", fmt.Sprintf("dir=%s", stateDir), "--tpm2", "--ctrl", "type=tcp,port=2322", "--server", "type=tcp,port=2321", "--flags", "not-need-init,startup-clear")
	if err := serverCmd.Start(); err != nil {
		return nil, err
	}

	device := &TpmEmulator{
		port:        2321,
		controlPort: 2322,
		stateDir:    stateDir,
		cmd:         serverCmd,
	}

	started := false
	timeout := time.Now().Add(3 * time.Second) // wait for the service startup for 3 seconds
	for time.Now().Before(timeout) {
		dev, err := net.Dial("tcp", fmt.Sprintf(":%d", device.port))
		if err != nil {
			continue
		}
		_ = dev.Close()

		started = true
		break
	}

	if !started {
		return nil, fmt.Errorf("swtpm instance timed out to start")
	}

	return device, nil
}

func (s *TpmEmulator) Stop() {
	err := s.cmd.Process.Kill()
	if err != nil {
		log.Print(err)
	}
	_ = os.RemoveAll(s.stateDir)
}

func (s *TpmEmulator) TctiEnvvar() string {
	return fmt.Sprintf(`TPM2TOOLS_TCTI=swtpm:host=localhost,port=%d`, s.port)
}

func TestTpm2ToConfig(t *testing.T) {
	var tests = []struct {
		pin      Tpm2Pin
		expected Tpm2Config
	}{{
		pin:      Tpm2Pin{},
		expected: Tpm2Config{},
	}, {
		pin: Tpm2Pin{
			Hash:    "hash",
			Key:     "key",
			JwkPub:  "jwkpun",
			JwkPriv: "jwkpriv",
			PcrBank: "pcrbank",
			PcrIds:  "pcrids",
		},

		expected: Tpm2Config{
			Hash:    "hash",
			Key:     "key",
			PcrBank: "pcrbank",
			PcrIds:  "pcrids",
		},
	}}

	for _, test := range tests {
		c, err := test.pin.toConfig()

		require.NoError(t, err)
		require.Equal(t, test.expected, c)
	}
}
