package infisical

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"pq-crypto-service/internal/keystore"
	"pq-crypto-service/internal/secmem"
)

var (
	ErrSecretNotFound  = keystore.ErrSecretNotFound
	ErrCorruptedBundle = keystore.ErrCorruptedBundle
	ErrAuthFailed      = errors.New("échec d'authentification Infisical Universal Auth")
	// ErrLegacyLayout signale une paire stockée dans l'ancien format scindé (deux secrets),
	// qui n'est plus lu : générer une nouvelle paire rendrait les données existantes illisibles.
	ErrLegacyLayout = fmt.Errorf("%w: paire de clés au format scindé historique détectée ; "+
		"la migrer vers le bundle atomique (voir CHANGELOG 0.2.0)", keystore.ErrBootstrapForbidden)
)

// KeypairBundle documente le format du secret atomique (commun à tous les coffres).
type KeypairBundle = keystore.KeypairBundle

// Options regroupe les seuls paramètres dont le client Infisical a besoin.
// Le paquet ne dépend ainsi pas de la configuration globale du service.
type Options struct {
	URL          string // URL de l'instance Infisical
	ClientID     string // Universal Auth : client ID
	ClientSecret []byte // Universal Auth : client secret (effacé par Close)
	CAFile       string // autorité de certification de l'instance (PEM) ; vide : CA du système
	ProjectID    string // identifiant du projet (workspace)
	Environment  string // environnement Infisical (prod, staging…)
	BundleName   string // secret atomique contenant la paire (défaut : DefaultBundleName)
	// LegacyPubKeyName et LegacyPrivKeyName nomment les secrets de l'ancien format scindé.
	// Ils ne sont plus lus : leur présence bloque seulement la génération d'une nouvelle paire.
	LegacyPubKeyName  string
	LegacyPrivKeyName string
	Algorithm         string // algorithme attendu dans le bundle (vide : non vérifié)
}

type Client struct {
	mu         sync.Mutex
	caOnce     sync.Once
	opts       Options
	httpClient *http.Client
	token      string
	tokenExp   time.Time
}

// NewClient crée un client Infisical. Les redirections HTTP sont refusées : une réponse 307
// ou 308 ferait renvoyer le corps (la clé privée, au bootstrap) à l'hôte désigné. Le transport
// n'accepte que TLS 1.3 et, si CAFile est fourni, ne fait confiance qu'à cette autorité.
// Le client garde sa propre copie du secret : l'appelant peut effacer la sienne.
func NewClient(opts Options) *Client {
	opts.ClientSecret = append([]byte(nil), opts.ClientSecret...)
	return &Client{opts: opts, httpClient: keystore.NewHTTPClient()}
}

// Close efface le client_secret et oublie le jeton : le client est inutilisable ensuite.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	secmem.Wipe(c.opts.ClientSecret)
	c.opts.ClientSecret = nil
	c.token = ""
	c.tokenExp = time.Time{}
	c.httpClient.CloseIdleConnections()
}

// loadCA charge l'autorité de CAFile dans le transport ; sans CAFile, la CA du système s'applique.
func (c *Client) loadCA() error {
	return keystore.LoadCA(c.httpClient, c.opts.CAFile, "INFISICAL_CA_FILE")
}

const DefaultBundleName = "PQ_KEM_KEYPAIR"

func (c *Client) bundleName() string {
	if c.opts.BundleName != "" {
		return c.opts.BundleName
	}
	return DefaultBundleName
}

// secretNamePattern restreint les noms de secrets : ils sont insérés dans le chemin de l'URL.
var secretNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}$`)

func validSecretName(name string) error {
	if !secretNamePattern.MatchString(name) || name == "." || name == ".." {
		return fmt.Errorf("nom de secret Infisical invalide %q : [A-Za-z0-9_.-] uniquement", name)
	}
	return nil
}

type loginResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int64  `json:"expiresIn"`
}

func (c *Client) authenticate(ctx context.Context) (string, error) {
	var caErr error
	c.caOnce.Do(func() { caErr = c.loadCA() })
	if caErr != nil {
		return "", caErr
	}
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		tok := c.token
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	if c.opts.ClientID == "" || len(c.opts.ClientSecret) == 0 {
		return "", fmt.Errorf("%w: client_id ou client_secret non configuré (ou client fermé)", ErrAuthFailed)
	}
	if !utf8.Valid(c.opts.ClientSecret) {
		return "", fmt.Errorf("%w: client_secret n'est pas de l'UTF-8 valide", ErrAuthFailed)
	}

	o := secmem.NewJSONObject(64 + len(c.opts.ClientID) + secmem.JSONStringLen(c.opts.ClientSecret))
	o.String("clientId", c.opts.ClientID)
	o.Text("clientSecret", c.opts.ClientSecret)
	body := o.Finish()
	defer body.Wipe()

	respBody, status, err := c.send(ctx, http.MethodPost, c.endpoint("api/v1/auth/universal-auth/login", nil), "", body.Bytes())
	if err != nil {
		return "", fmt.Errorf("connexion Infisical: %w", err)
	}
	defer secmem.Wipe(respBody)
	if status != http.StatusOK {
		return "", fmt.Errorf("%w: HTTP %d: %s", ErrAuthFailed, status, errorExcerpt(respBody))
	}

	var loginResp loginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil || loginResp.AccessToken == "" {
		return "", fmt.Errorf("%w: réponse de connexion illisible", ErrAuthFailed)
	}

	expSec := loginResp.ExpiresIn
	if expSec <= 0 {
		expSec = 3600
	}

	c.mu.Lock()
	c.token = loginResp.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(max(expSec-60, 1)) * time.Second)
	tok := c.token
	c.mu.Unlock()

	return tok, nil
}

// endpoint construit l'URL d'une ressource relative à l'instance Infisical.
func (c *Client) endpoint(relPath string, query url.Values) string {
	u, err := url.Parse(c.opts.URL)
	if err != nil {
		return ""
	}
	u.Path = path.Join("/", u.Path, relPath)
	u.RawQuery = query.Encode()
	return u.String()
}

// send exécute une requête et renvoie le corps de la réponse dans un tampon possédé, borné à
// maxResponseBytes, que l'appelant efface. reqBody appartient à l'appelant (effacé par lui).
func (c *Client) send(ctx context.Context, method, target, token string, reqBody []byte) ([]byte, int, error) {
	var header http.Header
	if token != "" {
		header = http.Header{"Authorization": {"Bearer " + token}}
	}
	return keystore.Send(ctx, c.httpClient, method, target, header, reqBody)
}

// errorExcerpt renvoie le début d'un corps d'erreur, borné, pour le message d'erreur.
func errorExcerpt(body []byte) string { return keystore.ErrorExcerpt(body) }

// call exécute une requête authentifiée et renvoie le corps d'une réponse 200/201.
func (c *Client) call(ctx context.Context, method, relPath string, query url.Values, reqBody []byte) ([]byte, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	respBody, status, err := c.send(ctx, method, c.endpoint(relPath, query), token, reqBody)
	if err != nil {
		return nil, fmt.Errorf("requête Infisical: %w", err)
	}
	switch status {
	case http.StatusOK, http.StatusCreated:
		return respBody, nil
	case http.StatusNotFound:
		secmem.Wipe(respBody)
		return nil, ErrSecretNotFound
	default:
		defer secmem.Wipe(respBody)
		return nil, fmt.Errorf("erreur API Infisical %d: %s", status, errorExcerpt(respBody))
	}
}

// getSecret renvoie la valeur d'un secret dans un tampon possédé, que l'appelant efface.
func (c *Client) getSecret(ctx context.Context, name string) ([]byte, error) {
	if err := validSecretName(name); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("workspaceId", c.opts.ProjectID)
	q.Set("environment", c.opts.Environment)

	respBody, err := c.call(ctx, http.MethodGet, "api/v3/secrets/raw/"+name, q, nil)
	if err != nil {
		return nil, err
	}
	defer secmem.Wipe(respBody)

	var secResp struct {
		Secret struct {
			SecretValue secmem.Text `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(respBody, &secResp); err != nil {
		secResp.Secret.SecretValue.Wipe()
		return nil, fmt.Errorf("%w: réponse de secret illisible", ErrCorruptedBundle)
	}
	return secResp.Secret.SecretValue, nil
}

// setSecret crée un secret. value appartient à l'appelant (effacée par lui).
func (c *Client) setSecret(ctx context.Context, name string, value []byte) error {
	if err := validSecretName(name); err != nil {
		return err
	}
	o := secmem.NewJSONObject(128 + len(c.opts.ProjectID) + len(c.opts.Environment) + secmem.JSONStringLen(value))
	o.String("workspaceId", c.opts.ProjectID)
	o.String("environment", c.opts.Environment)
	o.Text("secretValue", value)
	o.String("type", "shared")
	body := o.Finish()
	defer body.Wipe()

	respBody, err := c.call(ctx, http.MethodPost, "api/v3/secrets/raw/"+name, nil, body.Bytes())
	secmem.Wipe(respBody)
	return err
}

// FetchKeys lit la paire de clés depuis le bundle atomique. Les tampons renvoyés appartiennent
// à l'appelant, qui efface sk après usage.
//
// Sans bundle, ErrSecretNotFound n'est renvoyée que si aucune paire au format scindé historique
// n'existe : sinon ErrLegacyLayout bloque le démarrage plutôt que de générer une paire neuve.
func (c *Client) FetchKeys(ctx context.Context) ([]byte, []byte, error) {
	raw, err := c.getSecret(ctx, c.bundleName())
	switch {
	case err == nil:
		defer secmem.Wipe(raw)
		return c.parseBundle(raw)
	case errors.Is(err, ErrSecretNotFound):
		if err := c.checkNoLegacyLayout(ctx); err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrSecretNotFound
	default:
		return nil, nil, fmt.Errorf("accès bundle Infisical: %w", err)
	}
}

// parseBundle décode et vérifie un bundle ; sk est décodée directement dans un tampon possédé.
func (c *Client) parseBundle(raw []byte) (pk, sk []byte, err error) {
	return keystore.ParseBundle(raw, c.opts.Algorithm)
}

// checkNoLegacyLayout renvoie ErrLegacyLayout si un secret de l'ancien format scindé existe.
// Une erreur d'accès (autre que « introuvable ») est renvoyée : dans le doute, pas de bootstrap.
func (c *Client) checkNoLegacyLayout(ctx context.Context) error {
	for _, name := range []string{c.opts.LegacyPubKeyName, c.opts.LegacyPrivKeyName} {
		if name == "" {
			continue
		}
		v, err := c.getSecret(ctx, name)
		secmem.Wipe(v)
		switch {
		case err == nil:
			return fmt.Errorf("%w (secret %q)", ErrLegacyLayout, name)
		case !errors.Is(err, ErrSecretNotFound):
			return fmt.Errorf("vérification du format scindé historique: %w", err)
		}
	}
	return nil
}

// StoreKeys écrit la paire dans le bundle atomique. La clé privée n'est encodée que dans des
// tampons effaçables (Base64, JSON du bundle, corps de la requête), effacés au retour.
func (c *Client) StoreKeys(ctx context.Context, pkBytes, skBytes []byte) error {
	bundle := keystore.EncodeBundle(c.opts.Algorithm, pkBytes, skBytes, time.Now())
	defer bundle.Wipe()

	if err := c.setSecret(ctx, c.bundleName(), bundle.Bytes()); err != nil {
		return fmt.Errorf("stockage bundle atomique: %w", err)
	}
	return nil
}
