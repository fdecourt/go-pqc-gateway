package keystore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pq-crypto-service/internal/secmem"
)

const (
	// MaxResponseBytes borne une réponse réussie d'un coffre (un bundle ML-KEM-1024 fait ~9 Kio).
	MaxResponseBytes = 1 << 20
	// MaxErrorBodyBytes borne le corps d'erreur recopié dans le message, puis dans les logs.
	MaxErrorBodyBytes = 4 << 10
	// HTTPTimeout borne chaque appel à un coffre.
	HTTPTimeout = 10 * time.Second
)

// NewHTTPClient renvoie le client HTTP durci commun aux coffres de clés :
//   - TLS 1.3 uniquement ;
//   - aucun proxy d'environnement entre le service et son coffre ;
//   - redirections refusées : une réponse 307 ou 308 ferait renvoyer le corps (la clé privée,
//     au bootstrap) à l'hôte désigné ;
//   - pas de connexion persistante : chaque connexion se ferme dès sa réponse lue, ce qui libère
//     au plus tôt ses tampons (en-têtes avec le jeton, corps avec les secrets) pour qu'ils
//     soient effacés (voir WithErasure). Le client ne sert qu'à quelques requêtes au démarrage.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
			TLSHandshakeTimeout: HTTPTimeout,
			Proxy:               nil,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// LoadCA restreint la confiance du client à l'autorité PEM de caFile ; caFile vide : CA du
// système. varName nomme la variable d'environnement dans les messages d'erreur.
func LoadCA(c *http.Client, caFile, varName string) error {
	if caFile == "" {
		return nil
	}
	pem, err := os.ReadFile(filepath.Clean(caFile)) // #nosec G304 -- chemin fourni par l'opérateur
	if err != nil {
		return fmt.Errorf("lecture de %s: %w", varName, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s ne contient aucun certificat PEM valide", varName)
	}
	c.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return nil
}

// Send exécute une requête et renvoie le corps de la réponse dans un tampon possédé, borné à
// MaxResponseBytes, que l'appelant efface. reqBody appartient à l'appelant (effacé par lui) ;
// un corps non nil est envoyé en application/json.
func Send(ctx context.Context, c *http.Client, method, target string, header http.Header, reqBody []byte) ([]byte, int, error) {
	if target == "" {
		return nil, 0, errors.New("URL du coffre invalide")
	}
	var body io.Reader
	if reqBody != nil {
		body = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, err := secmem.ReadAll(resp.Body, resp.ContentLength, MaxResponseBytes)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("lecture de la réponse du coffre (HTTP %d): %w", resp.StatusCode, err)
	}
	return respBody, resp.StatusCode, nil
}

// ErrorExcerpt renvoie le début d'un corps d'erreur, borné, pour le message d'erreur.
func ErrorExcerpt(body []byte) string {
	return strings.ToValidUTF8(string(body[:min(len(body), MaxErrorBodyBytes)]), "?")
}
