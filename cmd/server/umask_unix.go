//go:build unix

package main

import "syscall"

// withSocketUmask exécute create avec un umask qui ne laisse passer que mode : le socket naît
// avec ses permissions finales, sans fenêtre entre sa création et le chmod qui suit.
// L'umask est global au processus ; il n'est modifié qu'au démarrage, avant tout service.
func withSocketUmask(mode uint32, create func() error) error {
	old := syscall.Umask(int(0o777 &^ mode))
	defer syscall.Umask(old)
	return create()
}
