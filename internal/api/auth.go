package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"

	"pq-crypto-service/internal/credential"
	"pq-crypto-service/internal/secmem"
)

// RequireTokenMiddleware exige un jeton porteur (Authorization: Bearer <secret>) sur toute
// route sauf /health, qui ne reçoit alors qu'un état minimal. Le secret présenté est haché
// puis comparé en temps constant à chaque empreinte admise : ni le nombre de jetons ni la
// position du bon ne transparaissent dans le temps de réponse. L'identité (le nom du jeton)
// alimente le journal d'accès, les limites par source et, si activée, la liaison d'identité.
//
// Une requête déjà authentifiée par certificat client (mTLS) garde cette identité ; le jeton
// est alors exigé en plus.
func RequireTokenMiddleware(tokens []credential.Token) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := ensureInfo(&r)
			name, ok := authenticateBearer(r.Header.Get("Authorization"), tokens)
			if !ok {
				if r.URL.Path == "/health" {
					info.auth.unauthenticated = true
					next.ServeHTTP(w, r)
					return
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="pq-crypto-service"`)
				respondError(w, http.StatusUnauthorized, "jeton requis", "en-tête Authorization: Bearer <jeton> obligatoire")
				return
			}
			info.auth.unauthenticated = false
			if info.auth.identity == "" {
				info.auth.identity = name
			}
			next.ServeHTTP(w, r)
		})
	}
}

// authenticateBearer renvoie le nom du jeton présenté s'il est admis.
func authenticateBearer(header string, tokens []credential.Token) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	secret := []byte(strings.TrimSpace(header[len(prefix):]))
	defer secmem.Wipe(secret)
	if len(secret) == 0 || len(secret) > 1024 {
		return "", false
	}
	presented := credential.HashToken(secret)
	defer secmem.Wipe(presented[:])
	match := -1
	for i := range tokens {
		// Toutes les entrées sont comparées, sans sortie anticipée.
		if subtle.ConstantTimeCompare(presented[:], tokens[i].Hash[:]) == 1 {
			match = i
		}
	}
	if match < 0 {
		return "", false
	}
	return tokens[match].Name, true
}

type peerKey struct{}

// ContextWithPeerUID attache à un contexte de connexion l'UID du pair d'un socket Unix,
// établi par l'écouteur (SO_PEERCRED). Utilisé par http.Server.ConnContext.
func ContextWithPeerUID(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, peerKey{}, uid)
}

// PeerIdentityMiddleware donne une identité « uid:<n> » aux requêtes arrivées par un socket
// Unix dont l'écouteur a vérifié les crédentials du pair, et les marque authentifiées.
func PeerIdentityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uid, ok := r.Context().Value(peerKey{}).(uint32); ok {
			info := ensureInfo(&r)
			if info.auth.identity == "" {
				info.auth.identity = "uid:" + strconv.FormatUint(uint64(uid), 10)
			}
			info.auth.peerVerified = true
		}
		next.ServeHTTP(w, r)
	})
}

// RequireIdentityMiddleware refuse (401) toute requête sans identité établie, sur les routes
// de chiffrement. Activé avec la liaison d'identité (BIND_CLIENT_IDENTITY) : une enveloppe ne
// peut être liée qu'à un client identifié.
func RequireIdentityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == metricsPath || ClientIdentity(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		respondError(w, http.StatusUnauthorized, "identité requise",
			"BIND_CLIENT_IDENTITY exige une identité : certificat client mTLS, jeton porteur ou socket Unix avec SOCKET_ALLOWED_UIDS")
	})
}

// identityContextPrefix sépare, dans le contexte de chiffrement effectif, l'identité du client
// du contexte qu'il fournit. Le séparateur 0x00 ne peut apparaître dans une identité (noms de
// certificats, de jetons et UID sont restreints à des caractères imprimables).
const identityContextPrefix = "IDENTITY:"

// BoundContext renvoie le contexte de chiffrement effectif d'une requête quand la liaison
// d'identité est active : « IDENTITY:<identité>\x00<contexte client> ». Une enveloppe scellée
// par un client ne peut alors être ouverte que par ce même client, quels que soient ses
// droits réseau : l'isolation entre locataires est cryptographique, pas seulement administrative.
func BoundContext(identity string, clientCtx []byte) []byte {
	out := make([]byte, 0, len(identityContextPrefix)+len(identity)+1+len(clientCtx))
	out = append(out, identityContextPrefix...)
	out = append(out, identity...)
	out = append(out, 0)
	return append(out, clientCtx...)
}
