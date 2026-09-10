//go:build linux

package crypto

import (
	"log"

	"golang.org/x/sys/unix"
)

// HardenProcess configure PR_SET_DUMPABLE=0 au niveau du noyau Linux.
// Cela réduit l'exposition aux core dumps et à l'inspection mémoire ptrace/proc par des processus pairs non-privilégiés.
func HardenProcess() {
	// PR_SET_DUMPABLE = 0 : Rend le processus non-dumpable (désactive ptrace, core dumps)
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("[SECURITY WARNING] Échec prctl PR_SET_DUMPABLE: %v", err)
	} else {
		log.Println("[SECURITY] Durcissement noyau actif: PR_SET_DUMPABLE=0 (protection anti-dump mémoire)")
	}
}
