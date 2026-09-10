package infisical

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/keystore"
)

var (
	ErrSecretNotFound  = keystore.ErrSecretNotFound
	ErrPartialKeypair  = keystore.ErrPartialKeypair
	ErrCorruptedBundle = errors.New("bundle de clés Infisical corrompu ou invalide")
	ErrAuthFailed      = errors.New("échec d'authentification Infisical Universal Auth")
)

type KeypairBundle struct {
	FormatVersion int    `json:"format_version"`
	Algorithm     string `json:"algorithm"`
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
	CreatedAt     string `json:"created_at"`
	Checksum      string `json:"checksum"`
}

func computeKeypairChecksum(pubB64, privB64 string) string {
	sum := sha256.Sum256([]byte(pubB64 + ":" + privB64))
	return hex.EncodeToString(sum[:])
}

type Client struct {
	mu         sync.Mutex
	cfg        *config.Config
	httpClient *http.Client
	token      string
	tokenExp   time.Time
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type loginResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int64  `json:"expiresIn"`
}

func (c *Client) authenticate(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		tok := c.token
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	if c.cfg.InfisicalClientID == "" || c.cfg.InfisicalClientSecret == "" {
		return "", fmt.Errorf("%w: client_id ou client_secret non configuré", ErrAuthFailed)
	}

	body, _ := json.Marshal(map[string]string{
		"clientId":     c.cfg.InfisicalClientID,
		"clientSecret": c.cfg.InfisicalClientSecret,
	})
	apiURL := fmt.Sprintf("%s/api/v1/auth/universal-auth/login", strings.TrimRight(c.cfg.InfisicalURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connexion Infisical (%s): %w", apiURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: HTTP %d: %s", ErrAuthFailed, resp.StatusCode, string(respBytes))
	}

	var loginResp loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", fmt.Errorf("décodage auth Infisical: %w", err)
	}

	expSec := loginResp.ExpiresIn
	if expSec <= 0 {
		expSec = 3600
	}

	c.mu.Lock()
	c.token = loginResp.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(expSec-60) * time.Second)
	tok := c.token
	c.mu.Unlock()

	return tok, nil
}

func (c *Client) doJSON(ctx context.Context, method, relPath string, query url.Values, body, result any) error {
	token, err := c.authenticate(ctx)
	if err != nil {
		return err
	}

	u, err := url.Parse(c.cfg.InfisicalURL)
	if err != nil {
		return fmt.Errorf("URL Infisical invalide: %w", err)
	}
	u.Path = path.Join(u.Path, relPath)
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sérialisation requête: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("requête Infisical: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrSecretNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("erreur API Infisical %d: %s", resp.StatusCode, string(respBytes))
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func (c *Client) getSecret(ctx context.Context, name string) (string, error) {
	q := url.Values{}
	q.Set("workspaceId", c.cfg.InfisicalProjectID)
	q.Set("environment", c.cfg.InfisicalEnv)

	var secResp struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v3/secrets/raw/"+url.PathEscape(name), q, nil, &secResp); err != nil {
		return "", err
	}
	return secResp.Secret.SecretValue, nil
}

func (c *Client) setSecret(ctx context.Context, name, value string) error {
	payload := map[string]string{
		"workspaceId": c.cfg.InfisicalProjectID,
		"environment": c.cfg.InfisicalEnv,
		"secretValue": value,
		"type":        "shared",
	}
	return c.doJSON(ctx, http.MethodPost, "/api/v3/secrets/raw/"+url.PathEscape(name), nil, payload, nil)
}

func decodeBase64Pair(pubB64, privB64 string) ([]byte, []byte, error) {
	pk, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("clé publique Base64: %w", err)
	}
	sk, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return nil, nil, fmt.Errorf("clé privée Base64: %w", err)
	}
	return pk, sk, nil
}

const DefaultBundleName = "PQ_KEM_KEYPAIR"

func (c *Client) bundleName() string {
	if c.cfg.InfisicalSecretBundleName != "" {
		return c.cfg.InfisicalSecretBundleName
	}
	return DefaultBundleName
}

func (c *Client) FetchKeys(ctx context.Context) ([]byte, []byte, error) {
	bundleName := c.bundleName()

	// 1. Tenter la lecture atomique du bundle
	if raw, err := c.getSecret(ctx, bundleName); err == nil && raw != "" {
		var bundle KeypairBundle
		if err := json.Unmarshal([]byte(raw), &bundle); err != nil {
			return nil, nil, fmt.Errorf("%w: json unmarshal: %v", ErrCorruptedBundle, err)
		}
		if bundle.FormatVersion != 1 {
			return nil, nil, fmt.Errorf("%w: version %d", ErrCorruptedBundle, bundle.FormatVersion)
		}
		if bundle.Algorithm != "" && c.cfg.Algorithm != "" && !strings.EqualFold(bundle.Algorithm, c.cfg.Algorithm) {
			return nil, nil, fmt.Errorf("%w: algo '%s' incompatible avec cfg '%s'", ErrCorruptedBundle, bundle.Algorithm, c.cfg.Algorithm)
		}
		if !strings.EqualFold(bundle.Checksum, computeKeypairChecksum(bundle.PublicKey, bundle.PrivateKey)) {
			return nil, nil, fmt.Errorf("%w: corruption détectée (checksum mismatch)", ErrCorruptedBundle)
		}
		return decodeBase64Pair(bundle.PublicKey, bundle.PrivateKey)
	} else if err != nil && !errors.Is(err, ErrSecretNotFound) {
		return nil, nil, fmt.Errorf("accès bundle Infisical: %w", err)
	}

	// 2. Repli / mode legacy : contrôle strict des 4 états
	pubB64, errPub := c.getSecret(ctx, c.cfg.InfisicalSecretPubKeyName)
	privB64, errPriv := c.getSecret(ctx, c.cfg.InfisicalSecretPrivKeyName)
	pubNotFound, privNotFound := errors.Is(errPub, ErrSecretNotFound), errors.Is(errPriv, ErrSecretNotFound)

	if pubNotFound && privNotFound {
		return nil, nil, ErrSecretNotFound
	}
	if errPub != nil && !pubNotFound {
		return nil, nil, fmt.Errorf("clé publique Infisical: %w", errPub)
	}
	if errPriv != nil && !privNotFound {
		return nil, nil, fmt.Errorf("clé privée Infisical: %w", errPriv)
	}
	if pubNotFound || privNotFound {
		return nil, nil, fmt.Errorf("%w: publique=%v, privée=%v", ErrPartialKeypair, !pubNotFound, !privNotFound)
	}

	return decodeBase64Pair(pubB64, privB64)
}

func (c *Client) StoreKeys(ctx context.Context, pkBytes, skBytes []byte) error {
	pubB64 := base64.StdEncoding.EncodeToString(pkBytes)
	privB64 := base64.StdEncoding.EncodeToString(skBytes)

	bundleName := c.bundleName()

	bundle := KeypairBundle{
		FormatVersion: 1,
		Algorithm:     c.cfg.Algorithm,
		PublicKey:     pubB64,
		PrivateKey:    privB64,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Checksum:      computeKeypairChecksum(pubB64, privB64),
	}

	// #nosec G117
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("sérialisation bundle: %w", err)
	}

	if err := c.setSecret(ctx, bundleName, string(bundleBytes)); err != nil {
		return fmt.Errorf("stockage bundle atomique: %w", err)
	}
	return nil
}
