package api

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestExtractIP_RightmostTrustedHop(t *testing.T) {
	req := httptest.NewRequest("GET", "/encrypt", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 198.51.100.42")

	// Avec trustProxy = true, l'IP de droite (198.51.100.42) doit être préférée à l'IP forgée de gauche
	ip := extractIP(req, true)
	if ip != "198.51.100.42" {
		t.Fatalf("attendu 198.51.100.42 (dernier saut), obtenu %s", ip)
	}

	// Avec trustProxy = false, X-Forwarded-For doit être ignoré au profit de RemoteAddr
	ipNoTrust := extractIP(req, false)
	if ipNoTrust != "10.0.0.1" {
		t.Fatalf("attendu 10.0.0.1, obtenu %s", ipNoTrust)
	}
}

func TestExtractIP_MalformedXFFFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/encrypt", nil)
	req.RemoteAddr = "192.168.1.10:54321"
	req.Header.Set("X-Forwarded-For", "invalid-ip-string, not-an-ip")

	// Si toutes les entrées XFF sont malformées, fallback sur RemoteAddr
	ip := extractIP(req, true)
	if ip != "192.168.1.10" {
		t.Fatalf("attendu fallback 192.168.1.10, obtenu %s", ip)
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
