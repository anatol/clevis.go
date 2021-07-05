package clevis

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptSss(t *testing.T) {
	const num = 5
	const threshold = 3

	var servers [num]*TangServer

	for i := range servers {
		s, err := NewTangServer(t)
		require.NoError(t, err)
		servers[i] = s
		defer s.Stop()
	}

	const inputText = "testing Shamir Secret Sharing"

	// encrypt a text using 'clevis-encrypt-sss' like this:
	// clevis-encrypt-sss '{"t":1, "pins": {"tang": [{"url":"router.lan:8888"},{"url":"router.lan:8888"}]}}' <<< "test"
	var tangConfigs [num]string
	for i, s := range servers {
		config, err := s.TangConfig(crypto.SHA256)
		require.NoError(t, err)
		tangConfigs[i] = config
	}
	sssConfig := fmt.Sprintf(`{"t":%d, "pins": {"tang": [%s]}}`, threshold, strings.Join(tangConfigs[:], ","))
	encryptCmd := exec.Command("clevis-encrypt-sss", sssConfig)
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

func TestEncryptSss(t *testing.T) {
	const num = 5
	const threshold = 3

	var servers [num]*TangServer

	for i := range servers {
		s, err := NewTangServer(t)
		require.NoError(t, err)
		servers[i] = s
		defer s.Stop()
	}

	const inputText = "testing Shamir Secret Sharing encryption"

	// encrypt a text using 'clevis-encrypt-sss' like this:
	// clevis-encrypt-sss '{"t":1, "pins": {"tang": [{"url":"router.lan:8888"},{"url":"router.lan:8888"}]}}' <<< "test"
	var tangConfigs [num]string
	for i, s := range servers {
		config, err := s.TangConfig(crypto.SHA256)
		require.NoError(t, err)
		tangConfigs[i] = config
	}
	sssConfig := fmt.Sprintf(`{"t":%d, "pins": {"tang": [%s]}}`, threshold, strings.Join(tangConfigs[:], ","))
	encrypted, err := EncryptSss([]byte(inputText), sssConfig)
	require.NoError(t, err)

	decryptedData1, err := Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, inputText, string(decryptedData1), "decryption failed")

	decryptCmd := exec.Command("clevis-decrypt-sss")
	decryptCmd.Stdin = bytes.NewReader(encrypted)
	var decryptedData2 bytes.Buffer
	decryptCmd.Stdout = &decryptedData2
	if testing.Verbose() {
		decryptCmd.Stderr = os.Stderr
	}
	require.NoError(t, decryptCmd.Run())
	require.Equal(t, inputText, decryptedData2.String(), "decryption failed")
}

func TestSssToConfig(t *testing.T) {
	var tests = []struct {
		pin      SssPin
		expected SssConfig
	}{{
		pin: SssPin{},
		expected: SssConfig{
			Pins: map[string][]json.RawMessage{},
		},
	}, {
		pin: SssPin{
			Threshold: 2,
			Jwe: []string{
				`eyJhbGciOiJFQ0RILUVTIiwiY2xldmlzIjp7InBpbiI6InRhbmciLCJ0YW5nIjp7ImFkdiI6eyJrZXlzIjpbeyJhbGciOiJFQ01SIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbImRlcml2ZUtleSJdLCJrdHkiOiJFQyIsIngiOiJBRUZsZGl4cGQ2eFdJMXJQaWdrX2lfZldfOVNMWGgzcTNoX0NibVJJSjJ2bW5uZVduZnlsdmczN3E5X0JlU3hoTHBUUWtxNTgwdFAtN1FpT29OZW00dWJnIiwieSI6IkFEOE1yb0ZJV1FJNG5tMXJWS09iMEltTzBZN0V6UHQxSFRRZlp4YWd2MklvTWV6OEhfdlY3UmE5ZlU3bEpob2Uzdi1UaDZ4My00NTQwRm9kZUl4eGlwaG4ifSx7ImFsZyI6IkVTNTEyIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJBRlpBcFV6WHp2alZKQ1pRWDFEZTNMVXVkSTdmaVdaY1pTM3Q0RjJ5cnhuMHRJdENZSVpyZnlnUGlDWmZWMWhWS2EzV3VIMllNcklTWlVQclNnaV9STjJkIiwieSI6IkFTRXl3LV85eGN3TkJudnBUN3RobUFGNXFIdjktVVBZZjM4QUM3eTVRQlZlalFIX0RPMXhwS3psVGJySEN6MGpyTWVFaXI4VHlXNXl3WklZbnFHelBCcG4ifV19LCJ1cmwiOiJodHRwOi8vMTkyLjE2OC40LjEwMDo3NTAwIn19LCJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQU9NaUxNQnlTSmZQUXNJY1p2WFdmRE51dm9FLTZSQ0E0T3c2enZJNHNKMzl0VndudXBpSVA2SExPYmJ3U0Fwc0xnVEtTaHVrZm9vWUdBeFFQelJtUkFKZSIsInkiOiJBQVp0WXJFSW03V0lVaEpfeEN5UlBlUFYwektzNk9USWl1cGVIcWVQV2UwRG5UZ2FyU2lpUnhGcmU1elNwWlMtM0pWNGtqVlUyQ3ZDbHpvSWR0U2ZFR2cxIn0sImtpZCI6IjdUQTBSZlBmc3NMaV9kZTlMY3dwRUJFSUU5TWVjLTdyS3JXMUZGZDBpY3MifQ..uM_SAsWf_ZqfY_SW.J27R4eeo.zR2ESZwdAZw-zAAVItsA8Q`,
				`eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY2xldmlzIjp7InBpbiI6InRwbTIiLCJ0cG0yIjp7Imhhc2giOiJzaGEyNTYiLCJqd2tfcHJpdiI6IkFNMEFJR0RXN1RMa2VYWTA3NGJ2VWVyWHJ4ZDVRU0RqZ3Z4bmxxVHozTEE0SWVKZkFCQ2J4dlZTcjZJTmV5OGRLV21qc3dOY0lHME5hci1wZzJNSXU2UkU2dHpqaVlGWmhhelVzQUpkYm1xMW5BeU5yWGRPQjN6QUdqZUU3VlhnclRXcm1hUF9ydjVUOWwzVVJ4LUwxTWZVaVpDU0RPUFpJREpScG5xTmQ3T2hSbnQ0QnNnYjFMaGtURFFwQ2g2OTdMWC1LXzFtNGpoOW1XaFBUR1NnLTA4emNwbFh2MjA3aTF2SkgzMGgteU9qTUtJRHNyd2dIbmhZakgydmN0bloxTDNZV3hkWUpRcFJld3pJUEdNMyIsImp3a19wdWIiOiJBQzRBQ0FBTEFBQUUwZ0FBQUJBQUlGTE5BZFIydGoxamtNWVUzUk1mTGhXOEJyRTRYYTlHNWRmQnFVYVV5TTA4Iiwia2V5IjoiZWNjIn19fQ..j8qFv2it0MpAXbv8.SbvwtB4gEGD7DeJpKX8.MJx3YwsjRReX5YxmgeZ6yA`,
				`eyJhbGciOiJkaXIiLCJjbGV2aXMiOnsicGluIjoic3NzIiwic3NzIjp7Imp3ZSI6WyJleUpoYkdjaU9pSkZRMFJJTFVWVElpd2lZMnhsZG1seklqcDdJbkJwYmlJNkluUmhibWNpTENKMFlXNW5JanA3SW1Ga2RpSTZleUpyWlhseklqcGJleUpoYkdjaU9pSkZRMDFTSWl3aVkzSjJJam9pVUMwMU1qRWlMQ0pyWlhsZmIzQnpJanBiSW1SbGNtbDJaVXRsZVNKZExDSnJkSGtpT2lKRlF5SXNJbmdpT2lKQlJVWnNaR2w0Y0dRMmVGZEpNWEpRYVdkclgybGZabGRmT1ZOTVdHZ3pjVE5vWDBOaWJWSkpTakoyYlc1dVpWZHVabmxzZG1jek4zRTVYMEpsVTNob1RIQlVVV3R4TlRnd2RGQXROMUZwVDI5T1pXMDBkV0puSWl3aWVTSTZJa0ZFT0UxeWIwWkpWMUZKTkc1dE1YSldTMDlpTUVsdFR6QlpOMFY2VUhReFNGUlJabHA0WVdkMk1rbHZUV1Y2T0VoZmRsWTNVbUU1WmxVM2JFcG9iMlV6ZGkxVWFEWjRNeTAwTlRRd1JtOWtaVWw0ZUdsd2FHNGlmU3g3SW1Gc1p5STZJa1ZUTlRFeUlpd2lZM0oySWpvaVVDMDFNakVpTENKclpYbGZiM0J6SWpwYkluWmxjbWxtZVNKZExDSnJkSGtpT2lKRlF5SXNJbmdpT2lKQlJscEJjRlY2V0hwMmFsWktRMXBSV0RGRVpUTk1WWFZrU1RkbWFWZGFZMXBUTTNRMFJqSjVjbmh1TUhSSmRFTlpTVnB5Wm5sblVHbERXbVpXTVdoV1MyRXpWM1ZJTWxsTmNrbFRXbFZRY2xObmFWOVNUakprSWl3aWVTSTZJa0ZUUlhsM0xWODVlR04zVGtKdWRuQlVOM1JvYlVGR05YRklkamt0VlZCWlpqTTRRVU0zZVRWUlFsWmxhbEZJWDBSUE1YaHdTM3BzVkdKeVNFTjZNR3B5VFdWRmFYSTRWSGxYTlhsM1drbFpibkZIZWxCQ2NHNGlmVjE5TENKMWNtd2lPaUpvZEhSd09pOHZNVGt5TGpFMk9DNDBMakV3TURvM05UQXdJbjE5TENKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWlhCcklqcDdJbU55ZGlJNklsQXROVEl4SWl3aWEzUjVJam9pUlVNaUxDSjRJam9pUVVGd05sWm5kRUZHTWtwTk9GbERXRTh5TW5oa1RUQndabGd6VFhkWGExTmpUMHhmTlZwcWJHUk1kMlpaVUhCblVuUkVVVVExZFhSclVrdHpaVGRGTjJRMk5IVldSbGxaY21Zd2FUTkplWEJOVWtsRGJscDJjU0lzSW5raU9pSkJRa3RYWmxsaFdsbHNhVUZtV1RnNFVqVXRWVFk1ZEdSQmFYcFBlWEZtYldWc1pITnhaVTVDTWtKRmRXZHljRlpqWXpGaWVYRjVNR05qYzBKWU56SmFWRVJ6WkhWM01sUnFiMEpxTUdreGJFVTBaemxZTWpGeUluMHNJbXRwWkNJNklqZFVRVEJTWmxCbWMzTk1hVjlrWlRsTVkzZHdSVUpGU1VVNVRXVmpMVGR5UzNKWE1VWkdaREJwWTNNaWZRLi5wN0c5SWRBWF9uLWFVR0t5LjRHZXUwbnNpMFFlUWF4NTY4bDJUQ2ZmTzM1VWhLNkJlQnBOMDQ3SGx0MVo5RXBJNTZWc29VbFhJLTlwVzBVazVQbU1yYmFEelpUM0N0a1FaYTc5NVZnLnJtV0ZzcUMyQVdwTWpzNUM2SFBCMlEiXSwicCI6Ii0wZk84WmdkSVpvZ1pSdDhxV3ZQVGZ4bWt1eFhCcDBxdHRnVWNXQ3pGdnMiLCJ0IjoxfX0sImVuYyI6IkEyNTZHQ00ifQ..vA9RMUFWJoB761HY.cTzNZq8.KoafYhQT8Un4jWml55U3DA`,
			},
		},
		expected: SssConfig{
			Threshold: 2,
			Pins: map[string][]json.RawMessage{
				"tang": {json.RawMessage(`{"url":"http://192.168.4.100:7500","thp":"Bp8XjITceWSN_7XFfW7WfJDTomE"}`)},
				"tpm2": {json.RawMessage(`{"hash":"sha256","key":"ecc"}`)},
				"sss":  {json.RawMessage(`{"t":1,"pins":{"tang":[{"url":"http://192.168.4.100:7500","thp":"Bp8XjITceWSN_7XFfW7WfJDTomE"}]}}`)},
			},
		},
	}}

	for _, test := range tests {
		c, err := test.pin.toConfig()

		assert.NoError(t, err)
		assert.Equal(t, test.expected, c)
	}
}
