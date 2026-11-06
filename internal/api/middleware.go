package api

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"pq-crypto-service/internal/secmem"
)

// GetCorrelationID extrait l'identifiant de corrélation du contexte de la requête.
func GetCorrelationID(r *http.Request) string {
	if info := infoOf(r); info != nil {
		return info.correlationID
	}
	return ""
}

// responseWriterInterceptor intercepte le code HTTP pour le logging d'accès.
type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
	bytesCount int
}

// Unwrap expose le ResponseWriter d'origine à http.ResponseController (échéances, flush).
func (w *responseWriterInterceptor) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseWriterInterceptor) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriterInterceptor) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesCount += n
	return n, err
}

// maxCorrelationIDLen borne l'identifiant accepté du client (un UUID en fait 36).
const maxCorrelationIDLen = 128

// validCorrelationID n'accepte que [A-Za-z0-9._:-]{1,128} : l'identifiant est renvoyé au
// client et journalisé, il ne doit donc porter ni contrôle, ni espace, ni volume arbitraire.
func validCorrelationID(s string) bool {
	if s == "" || len(s) > maxCorrelationIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

// CorrelationIDMiddleware garantit l'affectation et la propagation d'un identifiant de corrélation
// (X-Correlation-ID) sur chaque requête et réponse HTTP. Un identifiant client hors charte est
// remplacé par un identifiant aléatoire. Middleware le plus externe, il crée aussi le
// requestInfo que les suivants complètent.
func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get("X-Correlation-ID")
		if cid == "" {
			cid = r.Header.Get("X-Request-ID")
		}
		if !validCorrelationID(cid) {
			var b [16]byte
			_, _ = rand.Read(b[:])
			cid = hex.EncodeToString(b[:])
		}

		w.Header()["X-Correlation-Id"] = []string{cid}
		info := &requestInfo{
			correlationID: cid,
			bodyLimit:     SmallBodyLimit,
			mediaType:     parseMediaType(r.Header.Get("Content-Type")),
		}
		next.ServeHTTP(w, withRequestInfo(r, info))
	})
}

// maxLoggedField borne les valeurs fournies par le client qui sont recopiées dans le journal :
// un en-tête peut faire jusqu'à MaxHeaderBytes (1 Mio) et saturer la collecte de logs.
const maxLoggedField = 256

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// LoggerMiddleware journalise chaque requête HTTP entrante avec méthode, identifiant de corrélation, durée et statut.
func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		interceptor := &responseWriterInterceptor{ResponseWriter: w}

		next.ServeHTTP(interceptor, r)

		duration := time.Since(start)
		if interceptor.statusCode == 0 {
			interceptor.statusCode = http.StatusOK
		}

		slog.Info("http_request",
			slog.String("correlation_id", GetCorrelationID(r)),
			slog.String("method", r.Method),
			slog.String("path", truncate(r.URL.Path, maxLoggedField)),
			slog.Int("status", interceptor.statusCode),
			slog.Int64("duration_us", duration.Microseconds()),
			slog.Int("bytes", interceptor.bytesCount),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("client", ClientIdentity(r)),
			slog.String("user_agent", truncate(r.UserAgent(), maxLoggedField)),
		)
	})
}

// RecoveryMiddleware intercepte les paniques inattendues et renvoie une réponse JSON 500 propre.
// Si la réponse avait déjà commencé, un second WriteHeader serait ignoré et le JSON d'erreur
// viendrait corrompre le corps partiel : la connexion est alors interrompue (http.ErrAbortHandler)
// pour que le client voie une réponse tronquée plutôt qu'un 200 incohérent.
// Le collecteur de métriques est optionnel : un nil désactive simplement le comptage.
func RecoveryMiddleware(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tracked := &responseWriterInterceptor{ResponseWriter: w}
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				if m != nil {
					m.ObservePanic()
				}
				slog.Error("panic_recovered",
					slog.String("correlation_id", GetCorrelationID(r)),
					slog.String("path", r.URL.Path),
					slog.Any("panic", rec),
					slog.Bool("response_started", tracked.statusCode != 0),
					slog.String("stack", string(debug.Stack())),
				)
				if tracked.statusCode != 0 {
					panic(http.ErrAbortHandler)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(ErrorResponse{
					Error:   "erreur interne du serveur cryptographique",
					Code:    http.StatusInternalServerError,
					Details: "une condition inattendue a été rencontrée lors de l'exécution",
				})
			}()
			next.ServeHTTP(tracked, r)
		})
	}
}

// securityHeaders sont les en-têtes de sécurité, en clés canoniques. Les tranches de valeurs
// sont partagées entre toutes les réponses : net/http ne les modifie jamais (Header.Add
// réalloue une tranche pleine), et les poser directement évite une allocation par en-tête.
var securityHeaders = map[string][]string{
	"X-Content-Type-Options":            {"nosniff"},
	"X-Frame-Options":                   {"DENY"},
	"Content-Security-Policy":           {"default-src 'none'; frame-ancestors 'none'; sandbox"},
	"Cross-Origin-Opener-Policy":        {"same-origin"},
	"Cross-Origin-Embedder-Policy":      {"require-corp"},
	"Cross-Origin-Resource-Policy":      {"same-origin"},
	"X-Permitted-Cross-Domain-Policies": {"none"},
	"Referrer-Policy":                   {"no-referrer"},
	"Strict-Transport-Security":         {"max-age=63072000; includeSubDomains; preload"},
	"Cache-Control":                     {"no-store, no-cache, must-revalidate, proxy-revalidate"},
	"Pragma":                            {"no-cache"},
	"Expires":                           {"0"},
}

// SecurityHeadersMiddleware injecte des en-têtes HTTP de sécurité stricts (HSTS, CSP, nosniff, etc.).
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for k, v := range securityHeaders {
			h[k] = v
		}
		next.ServeHTTP(w, r)
	})
}

// clientAuth décrit l'authentification de la requête, posée par RequireClientCertMiddleware.
type clientAuth struct {
	unauthenticated bool   // admis sans identité (seul /health passe) : réponse minimale
	peerVerified    bool   // socket Unix dont le pair a été vérifié (SO_PEERCRED)
	identity        string // identité retenue : nom de certificat, de jeton ou « uid:<n> »
}

// ClientIdentity renvoie l'identité mTLS de la requête ("" sans certificat client).
func ClientIdentity(r *http.Request) string {
	if info := infoOf(r); info != nil {
		return info.auth.identity
	}
	return ""
}

// clientUnauthenticated indique une requête TLS admise sans certificat client (sonde /health).
func clientUnauthenticated(r *http.Request) bool {
	info := infoOf(r)
	return info != nil && info.auth.unauthenticated
}

// certificateNames renvoie les noms d'un certificat client : CN, SAN DNS et SAN URI.
func certificateNames(c *x509.Certificate) []string {
	names := make([]string, 0, 1+len(c.DNSNames)+len(c.URIs))
	if c.Subject.CommonName != "" {
		names = append(names, c.Subject.CommonName)
	}
	names = append(names, c.DNSNames...)
	for _, u := range c.URIs {
		names = append(names, u.String())
	}
	return names
}

// printableIdentity indique si une identité ne contient que des caractères imprimables ASCII,
// sans espace ni contrôle : elle est journalisée et peut entrer dans un contexte de chiffrement.
func printableIdentity(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// matchClientName renvoie le premier nom imprimable du certificat présent dans allowed
// (comparaison exacte, insensible à la casse) ; "" si aucun. Une liste vide accepte tout
// certificat, identifié par son premier nom imprimable ou, à défaut, son numéro de série.
func matchClientName(c *x509.Certificate, allowed []string) string {
	names := certificateNames(c)
	if len(allowed) == 0 {
		for _, n := range names {
			if printableIdentity(n) {
				return n
			}
		}
		return "serial:" + c.SerialNumber.String()
	}
	for _, n := range names {
		if !printableIdentity(n) {
			continue
		}
		for _, a := range allowed {
			if strings.EqualFold(n, a) {
				return n
			}
		}
	}
	return ""
}

// RequireClientCertMiddleware exige, en mTLS, un certificat client vérifié sur chaque requête
// arrivée par TLS, et, si allowedNames n'est pas vide, que l'un de ses noms (CN, SAN DNS ou
// URI) y figure : la CA cliente peut émettre des certificats pour d'autres services, qui ne
// doivent pas pour autant pouvoir déchiffrer. Exceptions : /health (sonde de liveness, qui ne
// reçoit alors qu'un état minimal) et les requêtes hors TLS, qui ne peuvent provenir que du
// socket Unix, protégé par ses permissions.
func RequireClientCertMiddleware(allowedNames []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				next.ServeHTTP(w, r)
				return
			}
			var auth clientAuth
			switch {
			case len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0:
				if r.URL.Path != "/health" {
					respondError(w, http.StatusUnauthorized, "certificat client requis", "authentification mTLS obligatoire sur cet écouteur")
					return
				}
				auth.unauthenticated = true
			default:
				auth.identity = matchClientName(r.TLS.VerifiedChains[0][0], allowedNames)
				if auth.identity == "" {
					respondError(w, http.StatusForbidden, "certificat client non autorisé", "le nom du certificat n'est pas dans TLS_CLIENT_ALLOWED_NAMES")
					return
				}
			}
			ensureInfo(&r).auth = auth
			next.ServeHTTP(w, r)
		})
	}
}

// jsonMediaType est le seul type de contenu admis pour les corps JSON.
const jsonMediaType = "application/json"

// binaryMediaType est le type des corps binaires (routes /encrypt, /decrypt, /wrap-key, /unwrap-key).
const binaryMediaType = "application/octet-stream"

// RequireContentTypeMiddleware refuse (415) tout corps dont le type n'est ni JSON ni binaire.
// Sans cette règle, un corps text/plain ou application/x-www-form-urlencoded contenant du JSON
// serait traité : c'est la forme que prend une requête forgée depuis un formulaire HTML.
// Une requête sans corps (Content-Length: 0) peut omettre l'en-tête.
func RequireContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
			// Aucune décompression : un corps compressé serait pris pour du JSON ou du binaire brut.
			discardBody(w, r)
			respondError(w, http.StatusUnsupportedMediaType, "encodage de contenu non supporté", "Content-Encoding doit être absent ou identity")
			return
		}
		if r.Header.Get("Content-Type") == "" && r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if mt := mediaTypeOf(r); mt != jsonMediaType && mt != binaryMediaType {
			discardBody(w, r)
			respondError(w, http.StatusUnsupportedMediaType, "type de contenu non supporté",
				"Content-Type attendu : "+jsonMediaType+" ou "+binaryMediaType)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxDiscardBytes borne la lecture d'un corps refusé quand aucun MaxBodySizeMiddleware ne
// l'a déjà limité (configuration construite à la main).
const maxDiscardBytes = 64 << 20

// discardWindow borne le temps consacré à lire le corps d'une requête refusée.
const discardWindow = time.Second

// discardBody lit et jette le corps d'une requête refusée (429, 503) avant la réponse.
//
// Sans cela, le serveur HTTP/1.1 de Go ferme la connexion dès qu'il reste plus de 256 Kio
// non lus : un client encore en train d'envoyer un gros corps reçoit un reset au lieu du
// statut et du Retry-After, et ne peut pas réessayer proprement.
//
// Un refus doit pourtant rester bon marché, sinon le rate-limit ne déleste plus rien : la
// lecture se fait par tampon fixe (aucune copie de la charge), dans la limite de
// MAX_PAYLOAD_BYTES et d'une fenêtre d'une seconde, puis la connexion est fermée. Un client
// qui envoie au goutte-à-goutte ne retient donc ni créneau ni connexion au-delà de cette
// fenêtre. Si le ResponseWriter ne permet pas de poser l'échéance, rien n'est lu.
func discardBody(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	w.Header().Set("Connection", "close")
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(discardWindow)); err != nil {
		return
	}
	drain(io.LimitReader(r.Body, maxDiscardBytes))
}

// drain lit r jusqu'au bout dans un tampon local effacé ensuite. io.Discard recyclerait un
// tampon partagé (sync.Pool) où resterait la fin d'un corps refusé, potentiellement sensible.
func drain(r io.Reader) {
	var chunk [8 << 10]byte
	defer secmem.Wipe(chunk[:])
	for {
		if _, err := r.Read(chunk[:]); err != nil {
			return
		}
	}
}
