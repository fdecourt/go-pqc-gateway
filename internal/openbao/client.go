// Package openbao stocke la paire de clés du service dans OpenBao (moteur KV version 2).
//
// OpenBao est un coffre open source (fork communautaire de HashiCorp Vault, licence MPL-2.0),
// auto-hébergeable : aucune dépendance à un éditeur pour retrouver ses clés. Le client vise
// la conservation à long terme sans risque de perte :
//   - la paire est écrite en check-and-set 0 : jamais d'écrasement d'une paire existante ;
//   - les métadonnées du secret exigent le check-and-set pour tout écrivain (cas_required) et
//     ne font jamais expirer de version (delete_version_after = 0) ;
//   - une paire supprimée (soft delete) ou détruite bloque le démarrage au lieu de provoquer
//     la génération d'une nouvelle paire : elle se restaure par « bao kv undelete » ;
//   - le bundle a le même format que dans les autres coffres (keystore.EncodeBundle).
//
// L'API est compatible HashiCorp Vault : le même client fonctionne avec un Vault KV v2.
package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"pq-crypto-service/internal/keystore"
	"pq-crypto-service/internal/secmem"
)

var (
	ErrSecretNotFound = keystore.ErrSecretNotFound
	ErrAuthFailed     = errors.New("échec d'authentification OpenBao")
	// ErrDeletedKeypair signale une paire dont la dernière version est supprimée ou détruite :
	// en générer une nouvelle rendrait illisibles les données chiffrées sous l'ancienne.
	ErrDeletedKeypair = fmt.Errorf("%w: la dernière version de la paire est supprimée ou détruite dans OpenBao ; "+
		"la restaurer (bao kv undelete / bao kv rollback) avant de redémarrer", keystore.ErrBootstrapForbidden)
	// ErrWriteConflict signale qu'une paire existe déjà au moment de l'écriture (check-and-set).
	ErrWriteConflict = errors.New("une paire existe déjà dans OpenBao (check-and-set) : écriture refusée")
)

// Méthodes d'authentification prises en charge.
const (
	AuthToken   = "token"
	AuthAppRole = "approle"
)

// Options regroupe les seuls paramètres dont le client OpenBao a besoin.
type Options struct {
	Addr         string // URL de l'instance (https://openbao:8200)
	CAFile       string // autorité de certification de l'instance (PEM) ; vide : CA du système
	Namespace    string // espace de noms OpenBao (en-tête X-Vault-Namespace) ; vide : racine
	AuthMethod   string // AuthToken ou AuthAppRole
	Token        []byte // jeton (AuthToken) ; effacé par Close
	RoleID       string // AppRole : role_id
	SecretID     []byte // AppRole : secret_id ; effacé par Close
	AppRoleMount string // point de montage AppRole (défaut : approle)
	KVMount      string // point de montage du moteur KV v2 (défaut : secret)
	SecretPath   string // chemin de la paire dans le moteur KV (défaut : pq-crypto-service/keypair)
	Algorithm    string // algorithme attendu dans le bundle (vide : non vérifié)
}

// Valeurs par défaut des options.
const (
	DefaultAppRoleMount = "approle"
	DefaultKVMount      = "secret"
	DefaultSecretPath   = "pq-crypto-service/keypair"
)

// Client implémente keystore.Store sur OpenBao KV v2.
type Client struct {
	mu         sync.Mutex
	caOnce     sync.Once
	caErr      error
	opts       Options
	httpClient *http.Client
	token      []byte
}

// NewClient crée un client OpenBao. Le client garde ses propres copies des secrets :
// l'appelant peut effacer les siennes. Voir keystore.NewHTTPClient pour le transport
// (TLS 1.3, sans proxy, sans redirection).
func NewClient(opts Options) *Client {
	opts.Token = append([]byte(nil), opts.Token...)
	opts.SecretID = append([]byte(nil), opts.SecretID...)
	if opts.AppRoleMount == "" {
		opts.AppRoleMount = DefaultAppRoleMount
	}
	if opts.KVMount == "" {
		opts.KVMount = DefaultKVMount
	}
	if opts.SecretPath == "" {
		opts.SecretPath = DefaultSecretPath
	}
	return &Client{opts: opts, httpClient: keystore.NewHTTPClient()}
}

// Close efface le jeton et le secret_id : le client est inutilisable ensuite.
//
// Un jeton obtenu par AppRole est d'abord révoqué auprès d'OpenBao : sa valeur a transité
// par des chaînes Go (en-tête HTTP), que le processus ne peut pas effacer ; révoqué, il ne
// vaut plus rien même s'il fuit (image mémoire, swap). Un jeton fourni par OPENBAO_TOKEN
// n'est pas révoqué : il sert à chaque démarrage.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.token) > 0 {
		c.revokeSelf()
	}
	secmem.Wipe(c.opts.Token)
	secmem.Wipe(c.opts.SecretID)
	secmem.Wipe(c.token)
	c.opts.Token, c.opts.SecretID, c.token = nil, nil, nil
	c.httpClient.CloseIdleConnections()
}

// revokeTimeout borne la révocation du jeton AppRole à la fermeture du client.
const revokeTimeout = 5 * time.Second

// revokeSelf révoque le jeton AppRole (politique « default » : auth/token/revoke-self).
// Un échec est signalé sans bloquer : le jeton expirera à la fin de son token_ttl.
func (c *Client) revokeSelf() {
	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()
	resp, status, err := keystore.Send(ctx, c.httpClient, http.MethodPost,
		c.endpoint("auth", "token", "revoke-self"), c.headers(c.token), nil)
	defer secmem.Wipe(resp)
	if err == nil && (status == http.StatusOK || status == http.StatusNoContent) {
		slog.Info("openbao_token_revoked")
		return
	}
	if err == nil {
		err = apiError(status, resp)
	}
	slog.Warn("openbao_token_revoke_failed", slog.String("error", err.Error()),
		slog.String("detail", "le jeton reste valide jusqu'à son expiration : garder un token_ttl court sur le rôle AppRole"))
}

// segmentPattern restreint les segments de chemin : ils sont insérés dans l'URL.
var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// validPath vérifie un chemin de montage ou de secret (segments séparés par « / »).
func validPath(name, p string) error {
	if p == "" {
		return fmt.Errorf("%s vide", name)
	}
	for _, seg := range strings.Split(p, "/") {
		if !segmentPattern.MatchString(seg) || seg == "." || seg == ".." {
			return fmt.Errorf("%s invalide %q : segments [A-Za-z0-9_.-] séparés par « / »", name, p)
		}
	}
	return nil
}

// Validate refuse une configuration incomplète ou dangereuse (https obligatoire en production).
func (o Options) Validate(production bool) error {
	u, err := url.Parse(o.Addr)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("OPENBAO_ADDR invalide (%q)", o.Addr)
	}
	if production && u.Scheme != "https" {
		return fmt.Errorf("OPENBAO_ADDR doit être en https:// en production (reçu %q) : la clé privée et le jeton y transitent", o.Addr)
	}
	switch o.AuthMethod {
	case AuthToken:
		if len(o.Token) == 0 {
			return errors.New("OPENBAO_AUTH=token exige OPENBAO_TOKEN (ou OPENBAO_TOKEN_FILE)")
		}
	case AuthAppRole:
		if o.RoleID == "" || len(o.SecretID) == 0 {
			return errors.New("OPENBAO_AUTH=approle exige OPENBAO_ROLE_ID et OPENBAO_SECRET_ID (ou OPENBAO_SECRET_ID_FILE)")
		}
	default:
		return fmt.Errorf("OPENBAO_AUTH invalide (%q) : token ou approle", o.AuthMethod)
	}
	for _, p := range []struct{ name, value string }{
		{"OPENBAO_APPROLE_MOUNT", o.AppRoleMount},
		{"OPENBAO_KV_MOUNT", o.KVMount},
		{"OPENBAO_SECRET_PATH", o.SecretPath},
	} {
		if p.value == "" {
			continue // valeur par défaut appliquée par NewClient
		}
		if err := validPath(p.name, p.value); err != nil {
			return err
		}
	}
	if o.Namespace != "" {
		if err := validPath("OPENBAO_NAMESPACE", o.Namespace); err != nil {
			return err
		}
	}
	return nil
}

// endpoint construit l'URL d'une ressource de l'API (/v1/...).
func (c *Client) endpoint(parts ...string) string {
	u, err := url.Parse(c.opts.Addr)
	if err != nil {
		return ""
	}
	u.Path = path.Join(append([]string{"/", u.Path, "v1"}, parts...)...)
	return u.String()
}

func (c *Client) headers(token []byte) http.Header {
	h := http.Header{}
	if len(token) > 0 {
		h.Set("X-Vault-Token", string(token))
	}
	if c.opts.Namespace != "" {
		h.Set("X-Vault-Namespace", c.opts.Namespace)
	}
	return h
}

// authenticate renvoie le jeton à utiliser : celui configuré, ou un jeton AppRole obtenu
// une fois au démarrage (le client ne sert qu'au démarrage, puis est fermé).
func (c *Client) authenticate(ctx context.Context) ([]byte, error) {
	c.caOnce.Do(func() { c.caErr = keystore.LoadCA(c.httpClient, c.opts.CAFile, "OPENBAO_CA_FILE") })
	if c.caErr != nil {
		return nil, c.caErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case len(c.token) > 0:
		return c.token, nil
	case c.opts.AuthMethod == AuthToken:
		if len(c.opts.Token) == 0 {
			return nil, fmt.Errorf("%w: jeton absent (ou client fermé)", ErrAuthFailed)
		}
		return c.opts.Token, nil
	case c.opts.AuthMethod != AuthAppRole:
		return nil, fmt.Errorf("%w: méthode %q non prise en charge", ErrAuthFailed, c.opts.AuthMethod)
	}
	if c.opts.RoleID == "" || len(c.opts.SecretID) == 0 {
		return nil, fmt.Errorf("%w: role_id ou secret_id absent (ou client fermé)", ErrAuthFailed)
	}

	o := secmem.NewJSONObject(64 + secmem.JSONStringLen([]byte(c.opts.RoleID)) + secmem.JSONStringLen(c.opts.SecretID))
	o.String("role_id", c.opts.RoleID)
	o.Text("secret_id", c.opts.SecretID)
	body := o.Finish()
	defer body.Wipe()

	resp, status, err := keystore.Send(ctx, c.httpClient, http.MethodPost,
		c.endpoint("auth", c.opts.AppRoleMount, "login"), c.headers(nil), body.Bytes())
	if err != nil {
		return nil, fmt.Errorf("connexion OpenBao: %w", err)
	}
	defer secmem.Wipe(resp)
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrAuthFailed, status, keystore.ErrorExcerpt(resp))
	}
	var login struct {
		Auth struct {
			ClientToken secmem.Text `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(resp, &login); err != nil || len(login.Auth.ClientToken) == 0 {
		login.Auth.ClientToken.Wipe()
		return nil, fmt.Errorf("%w: réponse de connexion illisible", ErrAuthFailed)
	}
	c.token = login.Auth.ClientToken
	return c.token, nil
}

// call exécute une requête authentifiée ; renvoie le corps (à effacer) et le statut HTTP.
func (c *Client) call(ctx context.Context, method, target string, reqBody []byte) ([]byte, int, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, 0, err
	}
	resp, status, err := keystore.Send(ctx, c.httpClient, method, target, c.headers(token), reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("requête OpenBao: %w", err)
	}
	return resp, status, nil
}

func apiError(status int, body []byte) error {
	return fmt.Errorf("erreur API OpenBao %d: %s", status, keystore.ErrorExcerpt(body))
}

// kvResponse lit la réponse d'une lecture KV v2 ; le bundle est lu sans jamais placer la
// clé privée dans une chaîne Go. Data.Data est nil quand la dernière version est supprimée.
type kvResponse struct {
	Data struct {
		Data     *keystore.BundleWire `json:"data"`
		Metadata struct {
			Version      int    `json:"version"`
			DeletionTime string `json:"deletion_time"`
			Destroyed    bool   `json:"destroyed"`
		} `json:"metadata"`
	} `json:"data"`
}

// FetchKeys lit la dernière version de la paire. Les tampons renvoyés appartiennent à
// l'appelant, qui efface sk après usage.
//
// ErrSecretNotFound n'est renvoyée que si le secret n'a jamais existé (aucune métadonnée) :
// une dernière version supprimée ou détruite renvoie ErrDeletedKeypair, qui bloque le démarrage.
func (c *Client) FetchKeys(ctx context.Context) ([]byte, []byte, error) {
	resp, status, err := c.call(ctx, http.MethodGet, c.endpoint(c.opts.KVMount, "data", c.opts.SecretPath), nil)
	if err != nil {
		return nil, nil, err
	}
	defer secmem.Wipe(resp)

	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil, c.classifyMissing(ctx)
	default:
		return nil, nil, apiError(status, resp)
	}

	var kv kvResponse
	defer func() {
		if kv.Data.Data != nil {
			kv.Data.Data.Wipe()
		}
	}()
	if err := json.Unmarshal(resp, &kv); err != nil {
		return nil, nil, fmt.Errorf("%w: réponse KV illisible", keystore.ErrCorruptedBundle)
	}
	md := kv.Data.Metadata
	if kv.Data.Data == nil || md.Destroyed || md.DeletionTime != "" {
		return nil, nil, ErrDeletedKeypair
	}
	pk, sk, err := kv.Data.Data.Keys(c.opts.Algorithm)
	if err != nil {
		return nil, nil, err
	}
	slog.Info("openbao_keys_loaded", slog.Int("version", md.Version), slog.String("path", c.opts.KVMount+"/"+c.opts.SecretPath))
	return pk, sk, nil
}

// classifyMissing distingue un secret jamais créé (ErrSecretNotFound : bootstrap autorisé)
// d'un secret dont la dernière version est supprimée ou détruite (ErrDeletedKeypair). Dans le
// doute (métadonnées inaccessibles), l'erreur est renvoyée : pas de bootstrap.
func (c *Client) classifyMissing(ctx context.Context) error {
	resp, status, err := c.call(ctx, http.MethodGet, c.endpoint(c.opts.KVMount, "metadata", c.opts.SecretPath), nil)
	if err != nil {
		return fmt.Errorf("vérification des métadonnées OpenBao: %w", err)
	}
	defer secmem.Wipe(resp)
	switch status {
	case http.StatusNotFound:
		return ErrSecretNotFound
	case http.StatusOK:
		var md struct {
			Data struct {
				CurrentVersion int `json:"current_version"`
			} `json:"data"`
		}
		if err := json.Unmarshal(resp, &md); err != nil {
			return fmt.Errorf("métadonnées OpenBao illisibles: %w", err)
		}
		if md.Data.CurrentVersion == 0 {
			return ErrSecretNotFound // métadonnées seules (créées avant toute écriture)
		}
		return ErrDeletedKeypair
	default:
		return fmt.Errorf("vérification des métadonnées OpenBao: %w", apiError(status, resp))
	}
}

// StoreKeys écrit la paire une seule fois, avec cas=0 : OpenBao refuse l'écriture si une
// paire existe déjà (ErrWriteConflict). Les métadonnées sont durcies ensuite (voir protect).
//
// L'ordre compte : dès que les métadonnées d'un secret existent, OpenBao exige la capacité
// « update » pour y écrire des données. Écrire la paire d'abord permet au service de se
// contenter de « create » sur la paire : son jeton ne peut jamais la remplacer.
func (c *Client) StoreKeys(ctx context.Context, pkBytes, skBytes []byte) error {
	bundle := keystore.EncodeBundle(c.opts.Algorithm, pkBytes, skBytes, time.Now())
	defer bundle.Wipe()
	body := secmem.NewBuffer(64 + bundle.Len())
	defer body.Wipe()
	body.WriteString(`{"options":{"cas":0},"data":`)
	body.Write(bundle.Bytes())
	body.WriteByte('}')

	resp, status, err := c.call(ctx, http.MethodPost, c.endpoint(c.opts.KVMount, "data", c.opts.SecretPath), body.Bytes())
	if err != nil {
		return fmt.Errorf("écriture de la paire dans OpenBao: %w", err)
	}
	defer secmem.Wipe(resp)
	switch {
	case status == http.StatusOK || status == http.StatusNoContent:
		c.protect(ctx)
		return nil
	case status == http.StatusBadRequest && strings.Contains(string(resp), "check-and-set"):
		return ErrWriteConflict
	default:
		return fmt.Errorf("écriture de la paire dans OpenBao: %w", apiError(status, resp))
	}
}

// protect impose le check-and-set à tout écrivain (un « bao kv put » sans -cas est refusé) et
// interdit l'expiration automatique des versions. Un échec n'annule pas l'écriture, déjà
// faite et sûre : il est signalé pour que l'opérateur pose ces métadonnées lui-même.
func (c *Client) protect(ctx context.Context) {
	meta := []byte(`{"cas_required":true,"delete_version_after":"0s","custom_metadata":{"owner":"pq-crypto-service","format":"keypair-bundle-v1"}}`)
	resp, status, err := c.call(ctx, http.MethodPost, c.endpoint(c.opts.KVMount, "metadata", c.opts.SecretPath), meta)
	defer secmem.Wipe(resp)
	if err == nil && (status == http.StatusOK || status == http.StatusNoContent) {
		return
	}
	if err == nil {
		err = apiError(status, resp)
	}
	slog.Warn("openbao_metadata_unprotected",
		slog.String("path", c.opts.KVMount+"/"+c.opts.SecretPath),
		slog.String("error", err.Error()),
		slog.String("detail", "paire stockée, mais cas_required et delete_version_after=0s non posés : "+
			"les poser (bao kv metadata put -cas-required=true -delete-version-after=0s) ou accorder create/update sur le chemin metadata"))
}
