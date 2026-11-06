//go:build linux

package crypto

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// HardenProcess réduit l'exposition de la mémoire du processus, où vivent les clés privées :
//   - PR_SET_DUMPABLE=0 : pas de core dump, et ptrace ou /proc/<pid>/mem refusés aux
//     processus non privilégiés du même utilisateur ;
//   - RLIMIT_CORE=0 : aucun core dump même si le drapeau précédent était rétabli (setuid,
//     changement de politique du noyau) ;
//   - PR_SET_NO_NEW_PRIVS=1 : un exec ultérieur ne peut acquérir aucun privilège.
//
// Chaque mesure est appliquée indépendamment ; un échec est journalisé sans arrêter le service.
func HardenProcess() {
	measures := []struct {
		name  string
		apply func() error
	}{
		{"PR_SET_DUMPABLE=0", func() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }},
		{"RLIMIT_CORE=0", func() error { return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}) }},
		{"PR_SET_NO_NEW_PRIVS=1", func() error { return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }},
	}
	for _, m := range measures {
		if err := m.apply(); err != nil {
			slog.Warn("harden_failed", slog.String("measure", m.name), slog.String("error", err.Error()))
			continue
		}
		slog.Info("harden_enabled", slog.String("measure", m.name))
	}
}
