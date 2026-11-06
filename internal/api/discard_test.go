package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (c countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// rejectingServer refuse toute requête après discardBody, et compte les octets lus du corps.
func rejectingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	read := new(atomic.Int64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = countingBody{r.Body, read}
		discardBody(w, r)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv, read
}

// TestDiscardBody_LargeBodyGetsStatus vérifie qu'un gros corps refusé est lu en entier :
// le client reçoit le 503 et son Retry-After, et la connexion est fermée.
func TestDiscardBody_LargeBodyGetsStatus(t *testing.T) {
	srv, read := rejectingServer(t)
	const size = 4 << 20

	resp, err := http.Post(srv.URL, "application/octet-stream", bytes.NewReader(make([]byte, size)))
	if err != nil {
		t.Fatalf("requête refusée terminée en erreur réseau au lieu d'un statut: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("statut %d (Retry-After=%q), attendu 503", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if !resp.Close {
		t.Fatal("la connexion d'une requête refusée doit être fermée")
	}
	if got := read.Load(); got != size {
		t.Fatalf("corps lu: %d octets, attendu %d", got, size)
	}
}

// TestDiscardBody_SlowBodyIsCutOff vérifie qu'un client au goutte-à-goutte ne retient pas la
// connexion au-delà de la fenêtre de lecture.
func TestDiscardBody_SlowBodyIsCutOff(t *testing.T) {
	srv, _ := rejectingServer(t)

	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte("{")) }() // un octet, puis plus rien

	req, _ := http.NewRequest(http.MethodPost, srv.URL, pr)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	if elapsed := time.Since(start); elapsed > discardWindow+2*time.Second {
		t.Fatalf("connexion retenue %v par un corps qui n'arrive pas (fenêtre %v)", elapsed, discardWindow)
	}
}
