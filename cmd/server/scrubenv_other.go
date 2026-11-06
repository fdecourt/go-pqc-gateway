//go:build !linux

package main

// scrubEnviron : hors Linux, le bloc d'environnement initial n'est pas accessible ; seule la
// copie du runtime est retirée (os.Unsetenv).
func scrubEnviron(names ...string) error { return nil }
