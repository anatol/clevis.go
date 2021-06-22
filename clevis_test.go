package clevis

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	var tests = []struct {
		expected Pin
		raw      []byte
	}{{
		expected: Pin{
			Pin: "tang",
			Tang: &TangPin{
				Advertisement: json.RawMessage(`{"keys":[{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"AEFldixpd6xWI1rPigk_i_fW_9SLXh3q3h_CbmRIJ2vmnneWnfylvg37q9_BeSxhLpTQkq580tP-7QiOoNem4ubg","y":"AD8MroFIWQI4nm1rVKOb0ImO0Y7EzPt1HTQfZxagv2IoMez8H_vV7Ra9fU7lJhoe3v-Th6x3-4540FodeIxxiphn"},{"alg":"ES512","crv":"P-521","key_ops":["verify"],"kty":"EC","x":"AFZApUzXzvjVJCZQX1De3LUudI7fiWZcZS3t4F2yrxn0tItCYIZrfygPiCZfV1hVKa3WuH2YMrISZUPrSgi_RN2d","y":"ASEyw-_9xcwNBnvpT7thmAF5qHv9-UPYf38AC7y5QBVejQH_DO1xpKzlTbrHCz0jrMeEir8TyW5ywZIYnqGzPBpn"}]}`),
				URL:           "http://192.168.4.100:7500",
			},
		},
		raw: []byte(`eyJhbGciOiJFQ0RILUVTIiwiY2xldmlzIjp7InBpbiI6InRhbmciLCJ0YW5nIjp7ImFkdiI6eyJrZXlzIjpbeyJhbGciOiJFQ01SIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbImRlcml2ZUtleSJdLCJrdHkiOiJFQyIsIngiOiJBRUZsZGl4cGQ2eFdJMXJQaWdrX2lfZldfOVNMWGgzcTNoX0NibVJJSjJ2bW5uZVduZnlsdmczN3E5X0JlU3hoTHBUUWtxNTgwdFAtN1FpT29OZW00dWJnIiwieSI6IkFEOE1yb0ZJV1FJNG5tMXJWS09iMEltTzBZN0V6UHQxSFRRZlp4YWd2MklvTWV6OEhfdlY3UmE5ZlU3bEpob2Uzdi1UaDZ4My00NTQwRm9kZUl4eGlwaG4ifSx7ImFsZyI6IkVTNTEyIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJBRlpBcFV6WHp2alZKQ1pRWDFEZTNMVXVkSTdmaVdaY1pTM3Q0RjJ5cnhuMHRJdENZSVpyZnlnUGlDWmZWMWhWS2EzV3VIMllNcklTWlVQclNnaV9STjJkIiwieSI6IkFTRXl3LV85eGN3TkJudnBUN3RobUFGNXFIdjktVVBZZjM4QUM3eTVRQlZlalFIX0RPMXhwS3psVGJySEN6MGpyTWVFaXI4VHlXNXl3WklZbnFHelBCcG4ifV19LCJ1cmwiOiJodHRwOi8vMTkyLjE2OC40LjEwMDo3NTAwIn19LCJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQU9NaUxNQnlTSmZQUXNJY1p2WFdmRE51dm9FLTZSQ0E0T3c2enZJNHNKMzl0VndudXBpSVA2SExPYmJ3U0Fwc0xnVEtTaHVrZm9vWUdBeFFQelJtUkFKZSIsInkiOiJBQVp0WXJFSW03V0lVaEpfeEN5UlBlUFYwektzNk9USWl1cGVIcWVQV2UwRG5UZ2FyU2lpUnhGcmU1elNwWlMtM0pWNGtqVlUyQ3ZDbHpvSWR0U2ZFR2cxIn0sImtpZCI6IjdUQTBSZlBmc3NMaV9kZTlMY3dwRUJFSUU5TWVjLTdyS3JXMUZGZDBpY3MifQ..uM_SAsWf_ZqfY_SW.J27R4eeo.zR2ESZwdAZw-zAAVItsA8Q`),
	}, {
		expected: Pin{
			Pin: "sss",
			Sss: &SssPin{
				Prime:     "-0fO8ZgdIZogZRt8qWvPTfxmkuxXBp0qttgUcWCzFvs",
				Threshold: 1,
				Jwe:       []string{"eyJhbGciOiJFQ0RILUVTIiwiY2xldmlzIjp7InBpbiI6InRhbmciLCJ0YW5nIjp7ImFkdiI6eyJrZXlzIjpbeyJhbGciOiJFQ01SIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbImRlcml2ZUtleSJdLCJrdHkiOiJFQyIsIngiOiJBRUZsZGl4cGQ2eFdJMXJQaWdrX2lfZldfOVNMWGgzcTNoX0NibVJJSjJ2bW5uZVduZnlsdmczN3E5X0JlU3hoTHBUUWtxNTgwdFAtN1FpT29OZW00dWJnIiwieSI6IkFEOE1yb0ZJV1FJNG5tMXJWS09iMEltTzBZN0V6UHQxSFRRZlp4YWd2MklvTWV6OEhfdlY3UmE5ZlU3bEpob2Uzdi1UaDZ4My00NTQwRm9kZUl4eGlwaG4ifSx7ImFsZyI6IkVTNTEyIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJBRlpBcFV6WHp2alZKQ1pRWDFEZTNMVXVkSTdmaVdaY1pTM3Q0RjJ5cnhuMHRJdENZSVpyZnlnUGlDWmZWMWhWS2EzV3VIMllNcklTWlVQclNnaV9STjJkIiwieSI6IkFTRXl3LV85eGN3TkJudnBUN3RobUFGNXFIdjktVVBZZjM4QUM3eTVRQlZlalFIX0RPMXhwS3psVGJySEN6MGpyTWVFaXI4VHlXNXl3WklZbnFHelBCcG4ifV19LCJ1cmwiOiJodHRwOi8vMTkyLjE2OC40LjEwMDo3NTAwIn19LCJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQUFwNlZndEFGMkpNOFlDWE8yMnhkTTBwZlgzTXdXa1NjT0xfNVpqbGRMd2ZZUHBnUnREUUQ1dXRrUktzZTdFN2Q2NHVWRllZcmYwaTNJeXBNUklDblp2cSIsInkiOiJBQktXZllhWllsaUFmWTg4UjUtVTY5dGRBaXpPeXFmbWVsZHNxZU5CMkJFdWdycFZjYzFieXF5MGNjc0JYNzJaVERzZHV3MlRqb0JqMGkxbEU0ZzlYMjFyIn0sImtpZCI6IjdUQTBSZlBmc3NMaV9kZTlMY3dwRUJFSUU5TWVjLTdyS3JXMUZGZDBpY3MifQ..p7G9IdAX_n-aUGKy.4Geu0nsi0QeQax568l2TCffO35UhK6BeBpN047Hlt1Z9EpI56VsoUlXI-9pW0Uk5PmMrbaDzZT3CtkQZa795Vg.rmWFsqC2AWpMjs5C6HPB2Q"},
			},
		},
		raw: []byte(`eyJhbGciOiJkaXIiLCJjbGV2aXMiOnsicGluIjoic3NzIiwic3NzIjp7Imp3ZSI6WyJleUpoYkdjaU9pSkZRMFJJTFVWVElpd2lZMnhsZG1seklqcDdJbkJwYmlJNkluUmhibWNpTENKMFlXNW5JanA3SW1Ga2RpSTZleUpyWlhseklqcGJleUpoYkdjaU9pSkZRMDFTSWl3aVkzSjJJam9pVUMwMU1qRWlMQ0pyWlhsZmIzQnpJanBiSW1SbGNtbDJaVXRsZVNKZExDSnJkSGtpT2lKRlF5SXNJbmdpT2lKQlJVWnNaR2w0Y0dRMmVGZEpNWEpRYVdkclgybGZabGRmT1ZOTVdHZ3pjVE5vWDBOaWJWSkpTakoyYlc1dVpWZHVabmxzZG1jek4zRTVYMEpsVTNob1RIQlVVV3R4TlRnd2RGQXROMUZwVDI5T1pXMDBkV0puSWl3aWVTSTZJa0ZFT0UxeWIwWkpWMUZKTkc1dE1YSldTMDlpTUVsdFR6QlpOMFY2VUhReFNGUlJabHA0WVdkMk1rbHZUV1Y2T0VoZmRsWTNVbUU1WmxVM2JFcG9iMlV6ZGkxVWFEWjRNeTAwTlRRd1JtOWtaVWw0ZUdsd2FHNGlmU3g3SW1Gc1p5STZJa1ZUTlRFeUlpd2lZM0oySWpvaVVDMDFNakVpTENKclpYbGZiM0J6SWpwYkluWmxjbWxtZVNKZExDSnJkSGtpT2lKRlF5SXNJbmdpT2lKQlJscEJjRlY2V0hwMmFsWktRMXBSV0RGRVpUTk1WWFZrU1RkbWFWZGFZMXBUTTNRMFJqSjVjbmh1TUhSSmRFTlpTVnB5Wm5sblVHbERXbVpXTVdoV1MyRXpWM1ZJTWxsTmNrbFRXbFZRY2xObmFWOVNUakprSWl3aWVTSTZJa0ZUUlhsM0xWODVlR04zVGtKdWRuQlVOM1JvYlVGR05YRklkamt0VlZCWlpqTTRRVU0zZVRWUlFsWmxhbEZJWDBSUE1YaHdTM3BzVkdKeVNFTjZNR3B5VFdWRmFYSTRWSGxYTlhsM1drbFpibkZIZWxCQ2NHNGlmVjE5TENKMWNtd2lPaUpvZEhSd09pOHZNVGt5TGpFMk9DNDBMakV3TURvM05UQXdJbjE5TENKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWlhCcklqcDdJbU55ZGlJNklsQXROVEl4SWl3aWEzUjVJam9pUlVNaUxDSjRJam9pUVVGd05sWm5kRUZHTWtwTk9GbERXRTh5TW5oa1RUQndabGd6VFhkWGExTmpUMHhmTlZwcWJHUk1kMlpaVUhCblVuUkVVVVExZFhSclVrdHpaVGRGTjJRMk5IVldSbGxaY21Zd2FUTkplWEJOVWtsRGJscDJjU0lzSW5raU9pSkJRa3RYWmxsaFdsbHNhVUZtV1RnNFVqVXRWVFk1ZEdSQmFYcFBlWEZtYldWc1pITnhaVTVDTWtKRmRXZHljRlpqWXpGaWVYRjVNR05qYzBKWU56SmFWRVJ6WkhWM01sUnFiMEpxTUdreGJFVTBaemxZTWpGeUluMHNJbXRwWkNJNklqZFVRVEJTWmxCbWMzTk1hVjlrWlRsTVkzZHdSVUpGU1VVNVRXVmpMVGR5UzNKWE1VWkdaREJwWTNNaWZRLi5wN0c5SWRBWF9uLWFVR0t5LjRHZXUwbnNpMFFlUWF4NTY4bDJUQ2ZmTzM1VWhLNkJlQnBOMDQ3SGx0MVo5RXBJNTZWc29VbFhJLTlwVzBVazVQbU1yYmFEelpUM0N0a1FaYTc5NVZnLnJtV0ZzcUMyQVdwTWpzNUM2SFBCMlEiXSwicCI6Ii0wZk84WmdkSVpvZ1pSdDhxV3ZQVGZ4bWt1eFhCcDBxdHRnVWNXQ3pGdnMiLCJ0IjoxfX0sImVuYyI6IkEyNTZHQ00ifQ..vA9RMUFWJoB761HY.cTzNZq8.KoafYhQT8Un4jWml55U3DA`),
	}, {
		expected: Pin{
			Pin: "tpm2",
			Tpm2: &Tpm2Pin{
				Hash:    "sha256",
				Key:     "ecc",
				JwkPub:  "AC4ACAALAAAE0gAAABAAIFLNAdR2tj1jkMYU3RMfLhW8BrE4Xa9G5dfBqUaUyM08",
				JwkPriv: "AM0AIGDW7TLkeXY074bvUerXrxd5QSDjgvxnlqTz3LA4IeJfABCbxvVSr6INey8dKWmjswNcIG0Nar-pg2MIu6RE6tzjiYFZhazUsAJdbmq1nAyNrXdOB3zAGjeE7VXgrTWrmaP_rv5T9l3URx-L1MfUiZCSDOPZIDJRpnqNd7OhRnt4Bsgb1LhkTDQpCh697LX-K_1m4jh9mWhPTGSg-08zcplXv207i1vJH30h-yOjMKIDsrwgHnhYjH2vctnZ1L3YWxdYJQpRewzIPGM3",
			},
		},
		raw: []byte(`eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY2xldmlzIjp7InBpbiI6InRwbTIiLCJ0cG0yIjp7Imhhc2giOiJzaGEyNTYiLCJqd2tfcHJpdiI6IkFNMEFJR0RXN1RMa2VYWTA3NGJ2VWVyWHJ4ZDVRU0RqZ3Z4bmxxVHozTEE0SWVKZkFCQ2J4dlZTcjZJTmV5OGRLV21qc3dOY0lHME5hci1wZzJNSXU2UkU2dHpqaVlGWmhhelVzQUpkYm1xMW5BeU5yWGRPQjN6QUdqZUU3VlhnclRXcm1hUF9ydjVUOWwzVVJ4LUwxTWZVaVpDU0RPUFpJREpScG5xTmQ3T2hSbnQ0QnNnYjFMaGtURFFwQ2g2OTdMWC1LXzFtNGpoOW1XaFBUR1NnLTA4emNwbFh2MjA3aTF2SkgzMGgteU9qTUtJRHNyd2dIbmhZakgydmN0bloxTDNZV3hkWUpRcFJld3pJUEdNMyIsImp3a19wdWIiOiJBQzRBQ0FBTEFBQUUwZ0FBQUJBQUlGTE5BZFIydGoxamtNWVUzUk1mTGhXOEJyRTRYYTlHNWRmQnFVYVV5TTA4Iiwia2V5IjoiZWNjIn19fQ..j8qFv2it0MpAXbv8.SbvwtB4gEGD7DeJpKX8.MJx3YwsjRReX5YxmgeZ6yA`),
	}}

	for _, test := range tests {
		msg, pin, err := Parse(test.raw)
		assert.NoError(t, err)
		assert.Equal(t, pin.Pin, test.expected.Pin)
		assert.Equal(t, pin.Tang, test.expected.Tang)
		assert.Equal(t, pin.Sss, test.expected.Sss)
		assert.Equal(t, pin.Tpm2, test.expected.Tpm2)
		assert.Equal(t, pin.Yubikey, test.expected.Yubikey)
		assert.NotNil(t, msg)
	}
}

func TestParseFailure(t *testing.T) {
	var tests = []struct {
		expectedMsg bool
		raw         []byte
	}{{
		// Cannot be parsed
		expectedMsg: false,
		raw:         []byte(`badmessage`),
	}, {
		// Valid obect, but the "clevis" header has been renamed to "clover"
		expectedMsg: true,
		raw:         []byte(`eyJhbGciOiJFQ0RILUVTIiwiY2xvdmVyIjp7InBpbiI6InRhbmciLCJ0YW5nIjp7ImFkdiI6eyJrZXlzIjpbeyJhbGciOiJFQ01SIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbImRlcml2ZUtleSJdLCJrdHkiOiJFQyIsIngiOiJBRUZsZGl4cGQ2eFdJMXJQaWdrX2lfZldfOVNMWGgzcTNoX0NibVJJSjJ2bW5uZVduZnlsdmczN3E5X0JlU3hoTHBUUWtxNTgwdFAtN1FpT29OZW00dWJnIiwieSI6IkFEOE1yb0ZJV1FJNG5tMXJWS09iMEltTzBZN0V6UHQxSFRRZlp4YWd2MklvTWV6OEhfdlY3UmE5ZlU3bEpob2Uzdi1UaDZ4My00NTQwRm9kZUl4eGlwaG4ifSx7ImFsZyI6IkVTNTEyIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJBRlpBcFV6WHp2alZKQ1pRWDFEZTNMVXVkSTdmaVdaY1pTM3Q0RjJ5cnhuMHRJdENZSVpyZnlnUGlDWmZWMWhWS2EzV3VIMllNcklTWlVQclNnaV9STjJkIiwieSI6IkFTRXl3LV85eGN3TkJudnBUN3RobUFGNXFIdjktVVBZZjM4QUM3eTVRQlZlalFIX0RPMXhwS3psVGJySEN6MGpyTWVFaXI4VHlXNXl3WklZbnFHelBCcG4ifV19LCJ1cmwiOiJodHRwOi8vMTkyLjE2OC40LjEwMDo3NTAwIn19LCJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQU9NaUxNQnlTSmZQUXNJY1p2WFdmRE51dm9FLTZSQ0E0T3c2enZJNHNKMzl0VndudXBpSVA2SExPYmJ3U0Fwc0xnVEtTaHVrZm9vWUdBeFFQelJtUkFKZSIsInkiOiJBQVp0WXJFSW03V0lVaEpfeEN5UlBlUFYwektzNk9USWl1cGVIcWVQV2UwRG5UZ2FyU2lpUnhGcmU1elNwWlMtM0pWNGtqVlUyQ3ZDbHpvSWR0U2ZFR2cxIn0sImtpZCI6IjdUQTBSZlBmc3NMaV9kZTlMY3dwRUJFSUU5TWVjLTdyS3JXMUZGZDBpY3MifQo..uM_SAsWf_ZqfY_SW.J27R4eeo.zR2ESZwdAZw-zAAVItsA8Q`),
	}, {
		// Valid message, but the clevis header is a simple string and not a json object
		expectedMsg: true,
		raw:         []byte(`eyJhbGciOiJFQ0RILUVTIiwiY2xldmlzIjoiLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0iLCJlbmMiOiJBMjU2R0NNIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQU9NaUxNQnlTSmZQUXNJY1p2WFdmRE51dm9FLTZSQ0E0T3c2enZJNHNKMzl0VndudXBpSVA2SExPYmJ3U0Fwc0xnVEtTaHVrZm9vWUdBeFFQelJtUkFKZSIsInkiOiJBQVp0WXJFSW03V0lVaEpfeEN5UlBlUFYwektzNk9USWl1cGVIcWVQV2UwRG5UZ2FyU2lpUnhGcmU1elNwWlMtM0pWNGtqVlUyQ3ZDbHpvSWR0U2ZFR2cxIn0sImtpZCI6IjdUQTBSZlBmc3NMaV9kZTlMY3dwRUJFSUU5TWVjLTdyS3JXMUZGZDBpY3MifQo..uM_SAsWf_ZqfY_SW.J27R4eeo.zR2ESZwdAZw-zAAVItsA8Q`),
	}}

	for _, test := range tests {
		msg, pin, err := Parse(test.raw)
		assert.Error(t, err)
		if test.expectedMsg {
			assert.NotNil(t, msg)
		} else {
			assert.Nil(t, msg)
		}
		assert.Nil(t, pin)
	}
}

func TestToConfig(t *testing.T) {
	var tests = []struct {
		pin      Pin
		expected Config
	}{{
		pin: Pin{
			Pin:  "tang",
			Tang: &TangPin{},
		},
		expected: Config{
			Pin:  "tang",
			Tang: &TangConfig{},
		},
	}, {
		pin: Pin{
			Pin: "sss",
			Sss: &SssPin{},
		},
		expected: Config{
			Pin: "sss",
			Sss: &SssConfig{},
		},
	}, {
		pin: Pin{
			Pin:  "tpm2",
			Tpm2: &Tpm2Pin{},
		},
		expected: Config{
			Pin:  "tpm2",
			Tpm2: &Tpm2Config{},
		},
	}, {
		pin: Pin{
			Pin:     "yubikey",
			Yubikey: &YubikeyPin{},
		},
		expected: Config{
			Pin:     "yubikey",
			Yubikey: &YubikeyConfig{},
		},
	}}

	for _, test := range tests {
		c, err := test.pin.ToConfig()
		assert.NoError(t, err)
		assert.Equal(t, test.expected.Pin, c.Pin)
		assert.Equal(t, test.expected.Tang, c.Tang)
		assert.Equal(t, test.expected.Yubikey, c.Yubikey)
	}
}
