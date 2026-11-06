package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsBinaryRequest(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{"Exact octet-stream", "application/octet-stream", true},
		{"Octet-stream with params", "application/octet-stream; charset=binary", true},
		{"JSON content type", "application/json", false},
		{"JSON with utf8", "application/json; charset=utf-8", false},
		{"Empty content type", "", false},
		{"Malformed content type", "application/;;;invalid", false},
		{"Text plain", "text/plain", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			actual := isBinaryRequest(req)
			if actual != tc.expected {
				t.Errorf("Content-Type %q: attendu %v, obtenu %v", tc.contentType, tc.expected, actual)
			}
		})
	}
}

func TestAcceptsBinary(t *testing.T) {
	tests := []struct {
		name     string
		accept   string
		expected bool
	}{
		{"Empty Accept header", "", false},
		{"Direct octet-stream", "application/octet-stream", true},
		{"Octet-stream with q=1.0", "application/octet-stream; q=1.0", true},
		{"Octet-stream with q=0.5", "application/octet-stream;q=0.5", true},
		{"Octet-stream with q=0", "application/octet-stream;q=0", false},
		{"Octet-stream with negative q", "application/octet-stream;q=-0.1", false},
		{"Multiple types with octet-stream preferred", "text/html, application/octet-stream;q=0.9, */*;q=0.8", true},
		{"Multiple types without octet-stream", "application/json, text/plain, */*", false},
		{"Malformed accept part", "invalid;;media,,, application/octet-stream", true},
		{"Malformed accept entirely", ";;;;;;,invalid", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			actual := acceptsBinary(req)
			if actual != tc.expected {
				t.Errorf("Accept %q: attendu %v, obtenu %v", tc.accept, tc.expected, actual)
			}
		})
	}
}
