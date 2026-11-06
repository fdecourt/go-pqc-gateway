//go:build goexperiment.runtimesecret

package secmem

import "runtime/secret"

// Erasure indique si Do efface réellement (binaire compilé avec GOEXPERIMENT=runtimesecret).
const Erasure = true

// Do exécute f sous runtime/secret.Do : à son retour, les registres et la pile utilisés par f
// (et tout ce qu'elle appelle) sont effacés, et les allocations faites par f, y compris dans
// les goroutines qu'elle lance, le sont dès que le ramasse-miettes les libère. Cela couvre ce
// que Wipe ne peut pas atteindre : chaînes Go (en-têtes HTTP), tampons internes de net/http et
// crypto/tls, temporaires des bibliothèques. Effectif sur linux/amd64 et linux/arm64 ; ailleurs,
// f est simplement appelée.
func Do(f func()) { secret.Do(f) }
