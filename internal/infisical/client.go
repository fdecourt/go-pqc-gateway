package infisical

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"pq-crypto-service/internal/keystore"
	"pq-crypto-service/internal/secmem"
)

var (
	ErrSecretNotFound  = keystore.ErrSecretNotFound
	ErrCorruptedBundle = errors.New("bundle de clés Infisical corrompu ou invalide")
	ErrAuthFailed      = errors.New("échec d'authentification Infisical Universal Auth")
	// ErrLegacyLayout signale une paire stockée dans l'ancien format scindé (deux secrets),
	// qui n'est plus lu : générer une nouvelle paire rendrait les données existantes illisibles.
	ErrLegacyLayout = fmt.Errorf("%w: paire de clés au format scindé historique détectée ; "+
		"la migrer vers le bundle atomique (voir CHANGELOG 0.2.0)", keystore.ErrBootstrapForbidden)
)

const (
	// maxResponseBytes borne une réponse réussie (un bundle ML-KEM-1024 hybride fait ~9 Kio).
	maxResponseBytes = 1 << 20
	// maxErrorBodyBytes borne le corps d'erreur recopié dans le message, puis dans les logs.
	maxErrorBodyBytes = 4 << 10
	// httpTimeout borne chaque appel à Infisical.
	httpTimeout = 10 * time.Second
)

// KeypairBundle documente le format (version 1) du secret atomique qui contient la paire.
// Le client ne l'utilise pas pour lire la clé privée : voir bundleWire.
type KeypairBundle struct {
	FormatVersion int    `json:"format_version"`
	Algorithm     string `json:"algorithm"`
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
	CreatedAt     string `json:"created_at"`
	Checksum      string `json:"checksum"`
}

// bundleWire lit un KeypairBundle sans jamais placer la clé privée dans une chaîne Go.
type bundleWire struct {
	FormatVersion int         `json:"format_version"`
	Algorithm     string      `json:"algorithm"`
	PublicKey     string      `json:"public_key"`
	PrivateKey    secmem.Text `json:"private_key"`
	Checksum      string      `json:"checksum"`
}

// keypairChecksum renvoie SHA-256(pubB64 ":" privB64), qui détecte une corruption du bundle.
func keypairChecksum(pubB64 string, privB64 []byte) []byte {
	h := sha256.New()
	h.Write([]byte(pubB64))
	h.Write([]byte{':'})
	h.Write(privB64)
	return h.Sum(nil)
}

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
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout: httpTimeout,
		Proxy:               nil, // jamais de proxy d'environnement entre le service et son coffre
	}
	return &Client{
		opts: opts,
		httpClient: &http.Client{
			Timeout:   httpTimeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
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
	if c.opts.CAFile == "" {
		return nil
	}
	pem, err := os.ReadFile(filepath.Clean(c.opts.CAFile))
	if err != nil {
		return fmt.Errorf("lecture de INFISICAL_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("INFISICAL_CA_FILE ne contient aucun certificat PEM valide")
	}
	c.httpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return nil
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
	if target == "" {
		return nil, 0, errors.New("URL Infisical invalide")
	}
	var body io.Reader
	if reqBody != nil {
		body = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, err := secmem.ReadAll(resp.Body, resp.ContentLength, maxResponseBytes)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("lecture de la réponse Infisical (HTTP %d): %w", resp.StatusCode, err)
	}
	return respBody, resp.StatusCode, nil
}

// errorExcerpt renvoie le début d'un corps d'erreur, borné, pour le message d'erreur.
func errorExcerpt(body []byte) string {
	return strings.ToValidUTF8(string(body[:min(len(body), maxErrorBodyBytes)]), "?")
}

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
	var b bundleWire
	defer b.PrivateKey.Wipe()
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, nil, fmt.Errorf("%w: JSON illisible", ErrCorruptedBundle)
	}
	if b.FormatVersion != 1 {
		return nil, nil, fmt.Errorf("%w: version %d", ErrCorruptedBundle, b.FormatVersion)
	}
	if b.Algorithm != "" && c.opts.Algorithm != "" && !strings.EqualFold(b.Algorithm, c.opts.Algorithm) {
		return nil, nil, fmt.Errorf("%w: algo '%s' incompatible avec cfg '%s'", ErrCorruptedBundle, b.Algorithm, c.opts.Algorithm)
	}
	want, err := hex.DecodeString(b.Checksum)
	if err != nil || subtle.ConstantTimeCompare(want, keypairChecksum(b.PublicKey, b.PrivateKey)) != 1 {
		return nil, nil, fmt.Errorf("%w: corruption détectée (checksum mismatch)", ErrCorruptedBundle)
	}

	pk, err = base64.StdEncoding.DecodeString(b.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: clé publique Base64 invalide", ErrCorruptedBundle)
	}
	sk = make([]byte, base64.StdEncoding.DecodedLen(len(b.PrivateKey)))
	n, err := base64.StdEncoding.Decode(sk, b.PrivateKey)
	if err != nil {
		secmem.Wipe(sk)
		return nil, nil, fmt.Errorf("%w: clé privée Base64 invalide", ErrCorruptedBundle)
	}
	return pk, sk[:n], nil
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
	pubB64 := base64.StdEncoding.EncodeToString(pkBytes)
	privB64 := secmem.NewBuffer(base64.StdEncoding.EncodedLen(len(skBytes)))
	defer privB64.Wipe()
	privB64.WriteBase64(skBytes)

	o := secmem.NewJSONObject(256 + len(pubB64) + privB64.Len() + len(c.opts.Algorithm))
	o.Int("format_version", 1)
	o.String("algorithm", c.opts.Algorithm)
	o.String("public_key", pubB64)
	o.Text("private_key", privB64.Bytes())
	o.String("created_at", time.Now().UTC().Format(time.RFC3339))
	o.String("checksum", hex.EncodeToString(keypairChecksum(pubB64, privB64.Bytes())))
	bundle := o.Finish()
	defer bundle.Wipe()

	if err := c.setSecret(ctx, c.bundleName(), bundle.Bytes()); err != nil {
		return fmt.Errorf("stockage bundle atomique: %w", err)
	}
	return nil
}
