package openbao

import (
	"strings"

	"pq-crypto-service/internal/keystore"
	"pq-crypto-service/internal/secmem"
)

// BackendName est la valeur de KEYSTORE qui sélectionne OpenBao.
const BackendName = "openbao"

func init() {
	keystore.Register(keystore.Backend{
		Name:       BackendName,
		SecretVars: []string{"OPENBAO_TOKEN", "OPENBAO_SECRET_ID"},
		Open:       open,
	})
}

// OptionsFromSettings lit la configuration OpenBao (variables OPENBAO_*). Sans OPENBAO_AUTH,
// la méthode se déduit des identifiants fournis : AppRole si OPENBAO_ROLE_ID est défini.
func OptionsFromSettings(s keystore.Settings) Options {
	o := Options{
		Addr:         s.Get("OPENBAO_ADDR", "https://openbao:8200"),
		CAFile:       s.Get("OPENBAO_CA_FILE", ""),
		Namespace:    s.Get("OPENBAO_NAMESPACE", ""),
		AuthMethod:   strings.ToLower(s.Get("OPENBAO_AUTH", "")),
		Token:        s.Secret("OPENBAO_TOKEN"),
		RoleID:       s.Get("OPENBAO_ROLE_ID", ""),
		SecretID:     s.Secret("OPENBAO_SECRET_ID"),
		AppRoleMount: s.Get("OPENBAO_APPROLE_MOUNT", DefaultAppRoleMount),
		KVMount:      s.Get("OPENBAO_KV_MOUNT", DefaultKVMount),
		SecretPath:   s.Get("OPENBAO_SECRET_PATH", DefaultSecretPath),
		Algorithm:    s.Algorithm(),
	}
	if o.AuthMethod == "" {
		o.AuthMethod = AuthToken
		if o.RoleID != "" {
			o.AuthMethod = AuthAppRole
		}
	}
	return o
}

func open(s keystore.Settings) (keystore.Store, error) {
	opts := OptionsFromSettings(s)
	defer secmem.Wipe(opts.Token) // NewClient garde ses propres copies
	defer secmem.Wipe(opts.SecretID)
	if err := opts.Validate(s.Production()); err != nil {
		return nil, err
	}
	return NewClient(opts), nil
}
