//go:build !goexperiment.runtimesecret

package secmem

// Erasure indique si Do efface réellement. Compiler avec GOEXPERIMENT=runtimesecret pour
// l'activer (c'est le cas de l'image Docker).
const Erasure = false

// Do appelle f directement : sans GOEXPERIMENT=runtimesecret, seul l'effacement explicite
// (Wipe) des tampons possédés par le service s'applique.
func Do(f func()) { f() }
