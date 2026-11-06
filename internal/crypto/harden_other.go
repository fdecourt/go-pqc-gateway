//go:build !linux

package crypto

import "log/slog"

// HardenProcess applique les durcissements disponibles pour les systèmes non-Linux.
func HardenProcess() {
	slog.Info("harden_skipped", slog.String("reason", "hôte non Linux : prctl indisponible"))
}
