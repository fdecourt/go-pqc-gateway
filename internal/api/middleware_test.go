package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryMiddleware(t *testing.T) {
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulation de crash inattendu")
	})

	handler := RecoveryMiddleware(nil)(panicHandler)
	req := httptest.NewRequest(http.MethodGet, "/test-panic", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("attendu code 500, obtenu %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("attendu Content-Type application/json, obtenu %q", ct)
	}
	body := rr.Body.String()
	if !bytes.Contains([]byte(body), []byte("erreur interne du serveur cryptographique")) {
		t.Errorf("corps de réponse inattendu: %s", body)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := SecurityHeadersMiddleware(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/test-headers", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"Content-Security-Policy":           "default-src 'none'; frame-ancestors 'none'; sandbox",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Embedder-Policy":      "require-corp",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Referrer-Policy":                   "no-referrer",
		"Strict-Transport-Security":         "max-age=63072000; includeSubDomains; preload",
		"Cache-Control":                     "no-store, no-cache, must-revalidate, proxy-revalidate",
		"Pragma":                            "no-cache",
		"Expires":                           "0",
	}

	for header, expectedVal := range expectedHeaders {
		if actualVal := rr.Header().Get(header); actualVal != expectedVal {
			t.Errorf("en-tête %s: attendu %q, obtenu %q", header, expectedVal, actualVal)
		}
	}
}

func TestMaxBodySizeMiddleware(t *testing.T) {
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	limit := int64(100)
	handler := MaxBodySizeMiddleware(limit)(echoHandler)

	// Cas 1 : corps sous la limite (50 octets)
	smallBody := bytes.Repeat([]byte("A"), 50)
	reqSmall := httptest.NewRequest(http.MethodPost, "/test-body", bytes.NewReader(smallBody))
	rrSmall := httptest.NewRecorder()
	handler.ServeHTTP(rrSmall, reqSmall)
	if rrSmall.Code != http.StatusOK {
		t.Fatalf("petit corps: attendu 200, obtenu %d", rrSmall.Code)
	}

	// Cas 2 : corps dépassant la limite (200 octets)
	largeBody := bytes.Repeat([]byte("B"), 200)
	reqLarge := httptest.NewRequest(http.MethodPost, "/test-body", bytes.NewReader(largeBody))
	rrLarge := httptest.NewRecorder()
	handler.ServeHTTP(rrLarge, reqLarge)
	if rrLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("grand corps: attendu 413, obtenu %d", rrLarge.Code)
	}
}

func TestCorrelationIDMiddleware(t *testing.T) {
	// Cas 1 : Génération automatique d'un Correlation ID si absent
	var capturedCID string
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCID = GetCorrelationID(r)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("accepted"))
	})
	handler := CorrelationIDMiddleware(baseHandler)

	req := httptest.NewRequest(http.MethodGet, "/test-cid-gen", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("attendu 202, obtenu %d", rr.Code)
	}
	respCID := rr.Header().Get("X-Correlation-ID")
	if respCID == "" {
		t.Fatal("X-Correlation-ID absent de la réponse HTTP")
	}
	if capturedCID != respCID {
		t.Fatalf("CID du contexte (%s) différent du CID de réponse (%s)", capturedCID, respCID)
	}

	// Cas 2 : Préservation d'un Correlation ID fourni par le client (X-Correlation-ID)
	clientCID := "trace-client-12345-abcde"
	reqWithCID := httptest.NewRequest(http.MethodGet, "/test-cid-preserved", nil)
	reqWithCID.Header.Set("X-Correlation-ID", clientCID)
	rrWithCID := httptest.NewRecorder()
	handler.ServeHTTP(rrWithCID, reqWithCID)

	if got := rrWithCID.Header().Get("X-Correlation-ID"); got != clientCID {
		t.Fatalf("CID client non préservé: obtenu %s, attendu %s", got, clientCID)
	}
	if capturedCID != clientCID {
		t.Fatalf("CID contexte non préservé: obtenu %s, attendu %s", capturedCID, clientCID)
	}

	// Cas 3 : Compatibilité avec X-Request-ID
	reqWithReqID := httptest.NewRequest(http.MethodGet, "/test-request-id", nil)
	reqWithReqID.Header.Set("X-Request-ID", "req-id-67890")
	rrWithReqID := httptest.NewRecorder()
	handler.ServeHTTP(rrWithReqID, reqWithReqID)

	if got := rrWithReqID.Header().Get("X-Correlation-ID"); got != "req-id-67890" {
		t.Fatalf("X-Request-ID non propagé en X-Correlation-ID: %s", got)
	}
}

func TestLoggerMiddleware(t *testing.T) {
	handler := CorrelationIDMiddleware(LoggerMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("logged"))
	})))

	req := httptest.NewRequest(http.MethodGet, "/test-log", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("attendu 200, obtenu %d", rr.Code)
	}
	if rr.Header().Get("X-Correlation-ID") == "" {
		t.Fatal("X-Correlation-ID manquant")
	}
}
