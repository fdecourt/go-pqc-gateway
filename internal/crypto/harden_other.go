//go:build !linux

package crypto

import "log"

// HardenProcess applique les durcissements disponibles pour les systèmes non-Linux.
func HardenProcess() {
	log.Println("[SECURITY] Environnement hôte non-Linux détecté. Les mécanismes Linux (prctl) sont ignorés.")
}
