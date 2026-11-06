package infisical

import (
	"fmt"
	"net/url"
	"strings"

	"pq-crypto-service/internal/keystore"
	"pq-crypto-service/internal/secmem"
)

// BackendName est la valeur de KEYSTORE qui sélectionne Infisical.
const BackendName = "infisical"

func init() {
	keystore.Register(keystore.Backend{
		Name:       BackendName,
		SecretVars: []string{"INFISICAL_CLIENT_SECRET"},
		Open:       open,
	})
}

// OptionsFromSettings lit la configuration Infisical (variables INFISICAL_*).
func OptionsFromSettings(s keystore.Settings) Options {
	return Options{
		URL:               s.Get("INFISICAL_URL", "https://infisical:8443"),
		ClientID:          s.Get("INFISICAL_CLIENT_ID", ""),
		ClientSecret:      s.Secret("INFISICAL_CLIENT_SECRET"),
		CAFile:            s.Get("INFISICAL_CA_FILE", ""),
		ProjectID:         s.Get("INFISICAL_PROJECT_ID", ""),
		Environment:       s.Get("INFISICAL_ENV", "prod"),
		BundleName:        s.Get("INFISICAL_SECRET_BUNDLE_NAME", DefaultBundleName),
		Algorithm:         s.Algorithm(),
		LegacyPubKeyName:  s.Get("INFISICAL_SECRET_PUBKEY_NAME", "PQ_KEM_PUBLIC_KEY"),
		LegacyPrivKeyName: s.Get("INFISICAL_SECRET_PRIVKEY_NAME", "PQ_KEM_PRIVATE_KEY"),
	}
}

// Validate refuse une configuration dangereuse : en production, l'URL doit être en https,
// car la clé privée et le client_secret y transitent.
func (o Options) Validate(production bool) error {
	if production {
		u, err := url.Parse(o.URL)
		if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
			return fmt.Errorf("INFISICAL_URL doit être en https:// en production (reçu %q) : la clé privée et le client_secret y transitent", o.URL)
		}
	}
	if o.BundleName != "" {
		return validSecretName(o.BundleName)
	}
	return nil
}

func open(s keystore.Settings) (keystore.Store, error) {
	opts := OptionsFromSettings(s)
	defer secmem.Wipe(opts.ClientSecret) // NewClient garde sa propre copie
	if err := opts.Validate(s.Production()); err != nil {
		return nil, err
	}
	return NewClient(opts), nil
}
