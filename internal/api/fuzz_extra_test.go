package api

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

func FuzzDecodeEnvelopeFields(f *testing.F) {
	// Corpus initial
	f.Add("", "", "", "data")
	f.Add("invalid", "invalid", "invalid", "data")
	f.Add(
		base64.StdEncoding.EncodeToString([]byte("encapKey")),
		base64.StdEncoding.EncodeToString([]byte("123456789012")),
		base64.StdEncoding.EncodeToString([]byte("cipherPayload")),
		"data",
	)

	f.Fuzz(func(t *testing.T, encap, nonce, data, name string) {
		// decodeEnvelopeFields ne doit jamais paniquer sur aucune entrée arbitraire
		k, n, d, err := decodeEnvelopeFields(encap, nonce, data, name)
		if err == nil {
			if k == nil || n == nil || d == nil {
				t.Fatalf("tranches nil retournées sans erreur")
			}
		}
	})
}

func FuzzExtractIP(f *testing.F) {
	// Corpus initial
	f.Add("192.168.1.1:8080", "", false)
	f.Add("192.168.1.1:8080", "10.0.0.1, 203.0.113.195", true)
	f.Add("[::1]:54321", "", false)
	f.Add("[2001:db8::1]:1234", "invalid-ip, 192.0.2.1", true)
	f.Add("garbage-remote-addr", ",,,", true)

	f.Fuzz(func(t *testing.T, remoteAddr, xff string, trustProxy bool) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remoteAddr
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		// extractIP ne doit jamais paniquer sur aucune chaîne arbitraire
		ip := extractIP(req, trustProxy)
		if ip == "" && remoteAddr != "" {
			t.Fatalf("extractIP a renvoyé une chaîne vide alors que RemoteAddr était %q", remoteAddr)
		}
	})
}
