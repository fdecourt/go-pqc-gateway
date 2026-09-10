package api

import (
	"container/list"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	// MaxTrackedIPs limite le nombre d'IPs suivies en mémoire vive.
	MaxTrackedIPs = 10000
)

type ipEntry struct {
	ip       string
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // horodatage unix en secondes
	element  *list.Element
}

// IPRateLimiter implémente un limiteur de débit Token Bucket thread-safe par IP avec éviction LRU O(1).
// Note résiduelle de modèle de menace : un limiteur par IP avec éviction n'arrête pas un attaquant à sources
// multiples massives (les adversaires finissent par évincer mutuellement leurs propres entrées).
type IPRateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*ipEntry
	lru        *list.List // Front: plus ancien, Back: plus récent
	limit      rate.Limit
	burst      int
	cleanupTTL int64 // durée de rétention en secondes
	stopChan   chan struct{}
	stopOnce   sync.Once
}

// NewIPRateLimiter initialise le limiteur de débit par IP avec LRU O(1).
func NewIPRateLimiter(ratePerSec float64, burstCapacity int) *IPRateLimiter {
	limiter := &IPRateLimiter{
		clients:    make(map[string]*ipEntry),
		lru:        list.New(),
		limit:      rate.Limit(ratePerSec),
		burst:      burstCapacity,
		cleanupTTL: int64((10 * time.Minute).Seconds()),
		stopChan:   make(chan struct{}),
	}

	go limiter.cleanupLoop()
	return limiter
}

// Stop arrête proprement la goroutine de nettoyage en arrière-plan.
func (l *IPRateLimiter) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
	})
}

// Allow vérifie si l'adresse IP a suffisamment de jetons pour effectuer une requête (O(1) sous verrou).
func (l *IPRateLimiter) Allow(ip string) bool {
	now := time.Now().Unix()

	l.mu.Lock()
	entry, exists := l.clients[ip]
	if exists {
		entry.lastSeen.Store(now)
		if entry.element != nil {
			l.lru.MoveToBack(entry.element)
		}
	} else {
		// Éviction O(1) de l'entrée la plus ancienne si capacité maximale atteinte
		if len(l.clients) >= MaxTrackedIPs {
			oldest := l.lru.Front()
			if oldest != nil {
				oldEntry := oldest.Value.(*ipEntry)
				l.lru.Remove(oldest)
				delete(l.clients, oldEntry.ip)
			} else {
				for k := range l.clients {
					delete(l.clients, k)
					break
				}
			}
		}

		entry = &ipEntry{
			ip:      ip,
			limiter: rate.NewLimiter(l.limit, l.burst),
		}
		entry.lastSeen.Store(now)
		entry.element = l.lru.PushBack(entry)
		l.clients[ip] = entry
	}
	limiter := entry.limiter
	l.mu.Unlock()

	return limiter.Allow()
}

func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopChan:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			l.mu.Lock()
			// Purge O(k) depuis la tête : la liste étant ordonnée chronologiquement, on s'arrête au premier non expiré
			for elem := l.lru.Front(); elem != nil; {
				entry := elem.Value.(*ipEntry)
				if now-entry.lastSeen.Load() > l.cleanupTTL {
					next := elem.Next()
					l.lru.Remove(elem)
					delete(l.clients, entry.ip)
					elem = next
				} else {
					break
				}
			}
			l.mu.Unlock()
		}
	}
}

// extractIP extrait l'IP du client. X-Forwarded-For n'est pris en compte que si trustProxy est explicitement activé.
// Les entrées sont analysées de droite à gauche (dernier saut proxy de confiance) et validées.
func extractIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(parts[i])
				if parsed := net.ParseIP(candidate); parsed != nil {
					return candidate
				}
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// RateLimitMiddleware applique la limitation de débit stricte par IP.
// Le collecteur de métriques est optionnel : un nil désactive simplement le comptage.
func RateLimitMiddleware(limiter *IPRateLimiter, trustProxy bool, m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// L'endpoint healthcheck local Docker n'est pas soumis au rate limit
			if r.URL.Path == "/health" && (strings.HasPrefix(r.RemoteAddr, "127.0.0.1") || strings.HasPrefix(r.RemoteAddr, "[::1]")) {
				next.ServeHTTP(w, r)
				return
			}

			ip := extractIP(r, trustProxy)
			if !limiter.Allow(ip) {
				if m != nil {
					m.ObserveRateLimited()
				}
				w.Header().Set("Retry-After", "2")
				respondError(w, http.StatusTooManyRequests, "limite de débit dépassée", "trop de requêtes cryptographiques soumises dans un intervalle court")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
