package keystore

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Settings donne à un coffre l'accès à sa configuration sans dépendre de internal/config :
// un coffre se branche sans toucher au reste du service.
type Settings interface {
	// Get renvoie une variable d'environnement non secrète (fallback si absente ou vide).
	Get(name, fallback string) string
	// Secret renvoie un secret déclaré dans Backend.SecretVars, lu (variable ou fichier
	// NAME_FILE) puis retiré de l'environnement au démarrage. La propriété du tampon est
	// transférée à l'appelant, qui l'efface ; nil si le secret n'est pas fourni.
	Secret(name string) []byte
	// Production indique si les garde-fous de production s'appliquent (https obligatoire…).
	Production() bool
	// Algorithm est l'algorithme KEM configuré, à vérifier contre celui du bundle stocké.
	Algorithm() string
}

// Backend décrit un coffre de clés branchable (Infisical, OpenBao, un KMS de cloud…).
//
// Contrat d'un coffre (voir aussi Store) :
//   - stocker la paire au format bundle (EncodeBundle / ParseBundle), identique pour tous
//     les coffres : c'est ce qui permet de passer d'un coffre à l'autre (Migrate) ;
//   - ne jamais écraser une paire existante : StoreKeys n'écrit que si aucune paire n'existe ;
//   - FetchKeys renvoie ErrSecretNotFound seulement si le coffre n'a JAMAIS contenu de paire.
//     Une paire supprimée, illisible ou inaccessible doit bloquer le démarrage
//     (ErrBootstrapForbidden ou une autre erreur), jamais déclencher une nouvelle génération :
//     les données chiffrées sous l'ancienne paire deviendraient illisibles ;
//   - Open valide sa configuration (fail-closed, https en production) ;
//   - s'il garde des secrets (jeton, identifiants), exposer Close() pour les effacer.
//
// Un KMS qui ne stocke pas de secrets (il chiffre seulement) s'intègre en enveloppant le
// bundle sous sa clé (Encrypt/Decrypt) et en stockant le résultat dans un coffre de secrets.
type Backend struct {
	// Name est la valeur de KEYSTORE qui sélectionne ce coffre (minuscules).
	Name string
	// SecretVars liste les variables secrètes du coffre : lues au démarrage, avant que le
	// bloc d'environnement du processus soit effacé, puis transmises via Settings.Secret.
	SecretVars []string
	// Open valide la configuration et construit le client du coffre.
	Open func(Settings) (Store, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Backend{}
)

// Register enregistre un coffre ; à appeler depuis la fonction init() de son paquet.
// Un nom vide ou déjà pris est une erreur de programmation (panique au démarrage).
func Register(b Backend) {
	registryMu.Lock()
	defer registryMu.Unlock()
	name := strings.ToLower(strings.TrimSpace(b.Name))
	if name == "" || b.Open == nil {
		panic("keystore.Register : nom et Open obligatoires")
	}
	if _, dup := registry[name]; dup {
		panic("keystore.Register : coffre déjà enregistré : " + name)
	}
	b.Name = name
	registry[name] = b
}

// Lookup renvoie le coffre enregistré sous ce nom (insensible à la casse).
func Lookup(name string) (Backend, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	b, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Backend{}, fmt.Errorf("coffre de clés %q inconnu (disponibles : %s)", name, strings.Join(namesLocked(), ", "))
	}
	return b, nil
}

// Names renvoie les noms des coffres enregistrés, triés.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return namesLocked()
}

func namesLocked() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// AllSecretVars renvoie les variables secrètes de tous les coffres enregistrés : elles sont
// toutes effacées de l'environnement du processus, coffre sélectionné ou non.
func AllSecretVars() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var vars []string
	for _, n := range namesLocked() {
		vars = append(vars, registry[n].SecretVars...)
	}
	return vars
}
