package api

import (
	"context"
	"mime"
	"net/http"
	"strings"
)

// requestInfo regroupe ce que les middlewares établissent sur une requête. Une seule valeur
// de contexte, posée par le middleware le plus externe et complétée par les suivants : le
// chemin chaud ne recopie pas la requête à chaque étape.
type requestInfo struct {
	correlationID string
	bodyLimit     int64
	mediaType     string // type de contenu normalisé ("" si absent ou illisible)
	auth          clientAuth
}

type requestInfoKey struct{}

// withRequestInfo attache un requestInfo neuf à la requête.
func withRequestInfo(r *http.Request, info *requestInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestInfoKey{}, info))
}

// infoOf renvoie le requestInfo de la requête, ou nil si aucun middleware ne l'a posé.
func infoOf(r *http.Request) *requestInfo {
	info, _ := r.Context().Value(requestInfoKey{}).(*requestInfo)
	return info
}

// ensureInfo renvoie le requestInfo de la requête, en le créant s'il manque (gestionnaire
// utilisé hors chaîne de middlewares, par exemple en test). r est alors remplacé.
func ensureInfo(r **http.Request) *requestInfo {
	if info := infoOf(*r); info != nil {
		return info
	}
	info := &requestInfo{bodyLimit: SmallBodyLimit, mediaType: parseMediaType((*r).Header.Get("Content-Type"))}
	*r = withRequestInfo(*r, info)
	return info
}

// parseMediaType normalise un Content-Type. Les valeurs courantes sont reconnues sans
// analyse générale (mime.ParseMediaType alloue une table de paramètres).
func parseMediaType(ct string) string {
	switch ct {
	case "":
		return ""
	case jsonMediaType, jsonMediaType + "; charset=utf-8", jsonMediaType + ";charset=utf-8", jsonMediaType + "; charset=UTF-8":
		return jsonMediaType
	case binaryMediaType:
		return binaryMediaType
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return strings.ToLower(mt)
}

// mediaTypeOf renvoie le type de contenu normalisé de la requête.
func mediaTypeOf(r *http.Request) string {
	if info := infoOf(r); info != nil {
		return info.mediaType
	}
	return parseMediaType(r.Header.Get("Content-Type"))
}
