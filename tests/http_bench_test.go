package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

// Benchmarks de bout en bout : requête HTTP complète à travers le routeur et ses middlewares.

func benchRouter(b *testing.B, suite string) http.Handler {
	b.Helper()
	engine, err := crypto.NewEngineForSuite(suite)
	if err != nil {
		b.Fatal(err)
	}
	r := api.NewRouter(&config.Config{Port: 8080, MaxPayloadBytes: 64 << 20, MaxConcurrentRequests: 64, RateLimitRPS: 0}, engine)
	b.Cleanup(r.Close)
	return r
}

func benchPost(b *testing.B, h http.Handler, path, ct string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	rr := httptest.NewRecorder()
	rr.Body.Grow(len(body) + len(body)/2 + 4096) // le recorder ne mesure pas sa propre croissance
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		b.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
	}
	return rr
}

func BenchmarkHTTP_WrapUnwrapKey(b *testing.B) {
	h := benchRouter(b, "ML-KEM-768")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	wrapBody := []byte(`{"plaintext_key":"` + base64.StdEncoding.EncodeToString(key) + `"}`)
	wrapped := benchPost(b, h, "/wrap-key", "application/json", wrapBody).Body.Bytes()
	unwrapBody := bytes.Replace(wrapped, []byte(`"wrapped_key"`), []byte(`"wrapped_key"`), 1)
	b.Run("wrap", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchPost(b, h, "/wrap-key", "application/json", wrapBody)
		}
	})
	b.Run("unwrap", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchPost(b, h, "/unwrap-key", "application/json", unwrapBody)
		}
	})
}

func benchLargeBodies(b *testing.B, size int) (jsonEnc, jsonDec, binEnc, binDec []byte, h http.Handler) {
	h = benchRouter(b, "ML-KEM-1024")
	plain := make([]byte, size)
	_, _ = rand.Read(plain)
	jsonEnc = []byte(`{"data":"` + base64.StdEncoding.EncodeToString(plain) + `"}`)
	jsonDec = append([]byte(nil), benchPost(b, h, "/encrypt", "application/json", jsonEnc).Body.Bytes()...)
	binEnc = plain
	binDec = append([]byte(nil), benchPost(b, h, "/encrypt", "application/octet-stream", plain).Body.Bytes()...)
	return
}

func BenchmarkHTTP_1MiB(b *testing.B) {
	jsonEnc, jsonDec, binEnc, binDec, h := benchLargeBodies(b, 1<<20)
	for _, c := range []struct {
		name, path, ct string
		body           []byte
	}{
		{"json-encrypt", "/encrypt", "application/json", jsonEnc},
		{"json-decrypt", "/decrypt", "application/json", jsonDec},
		{"binary-encrypt", "/encrypt", "application/octet-stream", binEnc},
		{"binary-decrypt", "/decrypt", "application/octet-stream", binDec},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(1 << 20)
			for i := 0; i < b.N; i++ {
				benchPost(b, h, c.path, c.ct, c.body)
			}
		})
	}
}
