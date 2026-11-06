package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

// testPKI génère une autorité, un certificat serveur (127.0.0.1) et un certificat client.
type testPKI struct {
	caPool             *x509.CertPool
	caFile             string
	serverCert, srvKey string
	client             tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, ips []net.IP) ([]byte, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	writePEM := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	srvDER, srvKey := issue(2, "pq-gateway", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1)})
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	cliDER, cliKey := issue(3, "client-app", x509.ExtKeyUsageClientAuth, nil)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return testPKI{
		caPool:     pool,
		caFile:     writePEM("ca.pem", "CERTIFICATE", caDER),
		serverCert: writePEM("server.pem", "CERTIFICATE", srvDER),
		srvKey:     writePEM("server-key.pem", "EC PRIVATE KEY", srvKeyDER),
		client:     tls.Certificate{Certificate: [][]byte{cliDER}, PrivateKey: cliKey},
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestMTLS_EndToEnd démarre l'écouteur réel en mTLS et vérifie : routes protégées refusées
// sans certificat client, acceptées avec, /health et la sonde -healthcheck toujours joignables.
func TestMTLS_EndToEnd(t *testing.T) {
	pki := newTestPKI(t)
	cfg := &config.Config{
		Environment: "production", ListenAddress: "127.0.0.1", Port: freePort(t),
		MaxPayloadBytes: 1 << 20, TLSCertFile: pki.serverCert, TLSKeyFile: pki.srvKey, TLSClientCAFile: pki.caFile,
		TLSMinVersion: tls.VersionTLS13, TLSClientAllowedNames: []string{"other-service", "CLIENT-APP"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	engine, err := crypto.NewEngineForSuite("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(cfg, engine)
	defer router.Close()
	listeners, err := openListeners(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(cfg, router)
	go func() { _ = srv.Serve(listeners[0]) }()
	defer srv.Close()

	base := "https://127.0.0.1:" + strconv.Itoa(cfg.Port)
	client := func(withCert bool) *http.Client {
		tlsCfg := &tls.Config{RootCAs: pki.caPool, MinVersion: tls.VersionTLS12}
		if withCert {
			tlsCfg.Certificates = []tls.Certificate{pki.client}
		}
		return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	status := func(c *http.Client, path string) int {
		resp, err := c.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := status(client(false), "/public-key"); got != http.StatusUnauthorized {
		t.Fatalf("/public-key sans certificat client: %d, attendu 401", got)
	}
	// /health reste joignable sans certificat, mais ne décrit pas le service.
	resp, err := client(false).Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	var health map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || health["status"] != "healthy" || health["algorithm"] != nil || health["uptime_seconds"] != nil {
		t.Fatalf("/health sans certificat client doit être minimal : %d %v", resp.StatusCode, health)
	}
	resp, err = client(true).Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if health["algorithm"] == nil {
		t.Fatalf("/health avec certificat client doit décrire le service : %v", health)
	}

	// TLS 1.2 est refusé : l'écouteur exige TLS 1.3.
	old := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pki.caPool, Certificates: []tls.Certificate{pki.client}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
	}}}
	if resp, err := old.Get(base + "/public-key"); err == nil {
		resp.Body.Close()
		t.Fatal("TLS 1.2 accepté alors que TLS_MIN_VERSION vaut 1.3")
	}
	if got := status(client(true), "/public-key"); got != http.StatusOK {
		t.Fatalf("/public-key avec certificat client: %d, attendu 200", got)
	}
	if code := runHealthcheck(cfg); code != 0 {
		t.Fatalf("sonde -healthcheck en TLS: code %d", code)
	}

	// Un certificat valide dont aucun nom n'est dans TLS_CLIENT_ALLOWED_NAMES est refusé (403).
	cfg.TLSClientAllowedNames = []string{"someone-else"}
	strict := api.NewRouter(cfg, engine)
	defer strict.Close()
	srv.Handler = strict
	if got := status(client(true), "/public-key"); got != http.StatusForbidden {
		t.Fatalf("certificat hors liste d'identités: %d, attendu 403", got)
	}
	srv.Handler = router

	// Un certificat client émis par une autre autorité est rejeté dès la poignée de main.
	other := newTestPKI(t)
	foreign := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pki.caPool, Certificates: []tls.Certificate{other.client}, MinVersion: tls.VersionTLS12,
	}}}
	if resp, err := foreign.Get(base + "/public-key"); err == nil {
		resp.Body.Close()
		t.Fatalf("certificat client d'une autorité étrangère accepté (statut %d)", resp.StatusCode)
	}
}
