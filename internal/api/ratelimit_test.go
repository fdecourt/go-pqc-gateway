package api

import (
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func TestClientIP_ForwardedForOnlyFromTrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "/encrypt", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 198.51.100.42")

	// Connexion depuis un proxy de confiance : l'adresse que ce proxy a vue (la plus à droite
	// qui n'est pas elle-même un proxy de confiance) fait foi.
	trusted := NewClientIPResolver(mustPrefixes(t, "10.0.0.0/8"))
	if ip := trusted(req); ip != "198.51.100.42" {
		t.Fatalf("attendu 198.51.100.42 (dernier saut non-proxy), obtenu %s", ip)
	}

	// Sans proxy déclaré, X-Forwarded-For est ignoré : la connexion fait foi.
	direct := NewClientIPResolver(nil)
	if ip := direct(req); ip != "10.0.0.1" {
		t.Fatalf("attendu 10.0.0.1, obtenu %s", ip)
	}

	// Connexion directe d'un client qui n'est pas un proxy de confiance : l'en-tête forgé est ignoré.
	req.RemoteAddr = "203.0.113.7:4444"
	if ip := trusted(req); ip != "203.0.113.7" {
		t.Fatalf("un client hors TRUSTED_PROXIES ne doit pas pouvoir se forger d'identité, obtenu %s", ip)
	}
}

func TestClientIP_SkipsChainedTrustedProxies(t *testing.T) {
	req := httptest.NewRequest("GET", "/encrypt", nil)
	req.RemoteAddr = "10.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "198.51.100.42, 10.0.0.2, 10.0.0.3")
	resolve := NewClientIPResolver(mustPrefixes(t, "10.0.0.0/8"))
	if ip := resolve(req); ip != "198.51.100.42" {
		t.Fatalf("les sauts de proxys de confiance doivent être sautés, obtenu %s", ip)
	}
}

func TestClientIP_MalformedXFFFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/encrypt", nil)
	req.RemoteAddr = "192.168.1.10:54321"
	req.Header.Set("X-Forwarded-For", "invalid-ip-string, not-an-ip")
	resolve := NewClientIPResolver(mustPrefixes(t, "192.168.1.10/32"))
	if ip := resolve(req); ip != "192.168.1.10" {
		t.Fatalf("attendu fallback 192.168.1.10, obtenu %s", ip)
	}
}

func TestClientIP_IPv6AggregatedPer64(t *testing.T) {
	resolve := NewClientIPResolver(nil)
	a := httptest.NewRequest("GET", "/", nil)
	a.RemoteAddr = "[2001:db8:1:2:aaaa::1]:1"
	b := httptest.NewRequest("GET", "/", nil)
	b.RemoteAddr = "[2001:db8:1:2:ffff::9]:2"
	c := httptest.NewRequest("GET", "/", nil)
	c.RemoteAddr = "[2001:db8:1:3::1]:3"
	if resolve(a) != resolve(b) {
		t.Fatalf("deux adresses du même /64 doivent partager la clé : %s != %s", resolve(a), resolve(b))
	}
	if resolve(a) == resolve(c) {
		t.Fatal("deux /64 distincts ne doivent pas partager la clé")
	}
	m := httptest.NewRequest("GET", "/", nil)
	m.RemoteAddr = "[::ffff:192.0.2.1]:4"
	if resolve(m) != "192.0.2.1" {
		t.Fatalf("une IPv4 mappée doit être ramenée à l'IPv4 : %s", resolve(m))
	}
}

func TestIsLoopbackRequest(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:1": true, "[::1]:1": true, "127.0.0.10:1": true, "10.0.0.1:1": false, "@": false, "": false} {
		r := httptest.NewRequest("GET", "/health", nil)
		r.RemoteAddr = addr
		if got := isLoopbackRequest(r); got != want {
			t.Errorf("%q: obtenu %v, attendu %v", addr, got, want)
		}
	}
}

func TestIPRateLimiter_PressureEvictionAvoidsGlobalDoS(t *testing.T) {
	limiter := NewIPRateLimiter(10, 10)
	defer limiter.Stop()

	// Remplir artificiellement le limiteur jusqu'à MaxTrackedIPs
	limiter.mu.Lock()
	for i := 0; i < MaxTrackedIPs; i++ {
		fakeIP := "10." + strconv.Itoa((i>>16)&0xFF) + "." + strconv.Itoa((i>>8)&0xFF) + "." + strconv.Itoa(i&0xFF)
		entry := &ipEntry{
			ip:      fakeIP,
			limiter: rate.NewLimiter(10, 10),
		}
		entry.lastSeen.Store(0) // timestamp dans le passé = expiré
		entry.element = limiter.lru.PushBack(entry)
		limiter.clients[fakeIP] = entry
	}
	limiter.mu.Unlock()

	// Une nouvelle IP arrive : elle ne doit PAS subir de déni de service global (fail-closed)
	newIP := "192.0.2.1"
	allowed := limiter.Allow(newIP)
	if !allowed {
		t.Fatal("RÉGRESSION DoS : le limiteur a rejeté une nouvelle IP légitime alors que des entrées expirées pouvaient être évincées !")
	}

	// Vérifier que la nouvelle IP est bien enregistrée
	limiter.mu.Lock()
	_, exists := limiter.clients[newIP]
	limiter.mu.Unlock()
	if !exists {
		t.Fatal("la nouvelle IP aurait dû être enregistrée après éviction")
	}
}

func TestIPRateLimiter_LiveEntriesEviction(t *testing.T) {
	limiter := NewIPRateLimiter(10, 10)
	defer limiter.Stop()

	// Remplir avec MaxTrackedIPs entrées VIVANTES (non expirées) avec un vrai limiter instancié
	now := time.Now().Unix()
	limiter.mu.Lock()
	for i := 0; i < MaxTrackedIPs; i++ {
		fakeIP := "10." + strconv.Itoa((i>>16)&0xFF) + "." + strconv.Itoa((i>>8)&0xFF) + "." + strconv.Itoa(i&0xFF)
		entry := &ipEntry{
			ip:      fakeIP,
			limiter: rate.NewLimiter(10, 10),
		}
		// Échelonner l'âge pour avoir un ordre chronologique clair, mais toutes bien vivantes (< cleanupTTL)
		entry.lastSeen.Store(now - int64(MaxTrackedIPs-i))
		entry.element = limiter.lru.PushBack(entry)
		limiter.clients[fakeIP] = entry
	}
	limiter.mu.Unlock()

	// L'arrivée d'une 10 001ème IP vivante doit être acceptée sans déni de service global
	newIP := "198.51.100.99"
	allowed := limiter.Allow(newIP)
	if !allowed {
		t.Fatal("RÉGRESSION DoS : le limiteur a rejeté une nouvelle IP alors qu'il devait évincer l'entrée la plus ancienne !")
	}

	limiter.mu.Lock()
	count := len(limiter.clients)
	_, exists := limiter.clients[newIP]
	_, oldestStillThere := limiter.clients["10.0.0.0"]
	limiter.mu.Unlock()

	if oldestStillThere {
		t.Fatal("l'entrée la plus ancienne ('10.0.0.0') aurait dû être évincée en premier (ordre LRU)")
	}
	if !exists {
		t.Fatal("la nouvelle IP n'a pas été insérée dans le registre")
	}
	if count > MaxTrackedIPs {
		t.Fatalf("dépassement de capacité : %d entrées, max attendu %d", count, MaxTrackedIPs)
	}
}
