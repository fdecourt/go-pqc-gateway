package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIPFunc renvoie la clé de source d'une requête, utilisée par le rate-limit et le
// plafond de concurrence par source : l'identité authentifiée (certificat, jeton, UID) quand
// il y en a une, sinon l'adresse réseau.
type ClientIPFunc func(r *http.Request) string

// ipv6KeyBits est la largeur de préfixe sous laquelle les adresses IPv6 sont agrégées : un
// abonné dispose d'un /64 entier, soit 2^64 adresses ; limiter par adresse n'y limiterait rien.
const ipv6KeyBits = 64

// NewClientIPResolver construit la fonction d'identité de source.
//
// X-Forwarded-For n'est consulté que si la connexion vient d'un proxy de trustedProxies :
// un client qui atteint le service directement ne peut pas se forger d'identité. L'en-tête
// est lu de droite à gauche en sautant les proxys de confiance : la première adresse qui n'en
// est pas un est celle que le dernier proxy de confiance a vue. Sans adresse exploitable,
// l'adresse de connexion fait foi. Les adresses IPv6 sont ramenées à leur /64.
func NewClientIPResolver(trustedProxies []netip.Prefix) ClientIPFunc {
	trusted := func(a netip.Addr) bool {
		for _, p := range trustedProxies {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return func(r *http.Request) string {
		if id := ClientIdentity(r); id != "" {
			return "id:" + id
		}
		remote, ok := remoteAddr(r)
		if !ok {
			return r.RemoteAddr // socket Unix : une seule source, clé commune
		}
		if len(trustedProxies) == 0 || !trusted(remote) {
			return ipKey(remote)
		}
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				break // en-tête malformé : ne rien deviner au-delà
			}
			if !trusted(a) {
				return ipKey(a)
			}
		}
		return ipKey(remote)
	}
}

// remoteAddr renvoie l'adresse IP de la connexion (false pour un socket Unix ou une valeur illisible).
func remoteAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ipKey normalise une adresse en clé : l'adresse IPv4 telle quelle, le /64 pour IPv6.
func ipKey(a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(ipv6KeyBits)
		return p.String()
	}
	return a.String()
}

// isLoopbackRequest indique si la connexion vient de la machine (sonde locale).
func isLoopbackRequest(r *http.Request) bool {
	a, ok := remoteAddr(r)
	return ok && a.IsLoopback()
}
