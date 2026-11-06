package api

import (
	"encoding/base64"
	"net/http/httptest"
	"net/netip"
	"testing"

	"pq-crypto-service/internal/secmem"
)

// FuzzDecodeDecryptRequest exerce le décodage strict d'une enveloppe JSON reçue.
func FuzzDecodeDecryptRequest(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`{"encapsulated_key":"invalid","nonce":"invalid","ciphertext":"invalid"}`))
	f.Add([]byte(`{"algorithm":"ML-KEM-768+AES-256-GCM","version":"GO-PQC-GATEWAY-V2","suite_id":1,"kid":"00",` +
		`"encapsulated_key":"` + base64.StdEncoding.EncodeToString([]byte("encapKey")) +
		`","nonce":"` + base64.StdEncoding.EncodeToString([]byte("123456789012")) +
		`","ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("cipherPayload")) + `","context":"c"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var req DecryptRequest
		if err := secmem.DecodeStrict(append([]byte(nil), data...), &req, false); err == nil {
			// Un décodage réussi ne laisse que des champs cohérents : complete() décide seul.
			_ = req.complete(req.Ciphertext)
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

	trusted := NewClientIPResolver([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	direct := NewClientIPResolver(nil)
	f.Fuzz(func(t *testing.T, remoteAddr, xff string, trustProxy bool) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remoteAddr
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		// Le résolveur ne doit jamais paniquer sur aucune chaîne arbitraire
		resolve := direct
		if trustProxy {
			resolve = trusted
		}
		if ip := resolve(req); ip == "" && remoteAddr != "" {
			t.Fatalf("clé vide alors que RemoteAddr était %q", remoteAddr)
		}
	})
}
