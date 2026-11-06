package main

import (
	"bytes"
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
)

// cgroupMemoryFiles sont les limites mémoire du conteneur, cgroup v2 puis v1.
var cgroupMemoryFiles = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

// memLimitShare est la part de la limite du conteneur visée par le ramasse-miettes : le reste
// couvre la pile, les tampons réseau et les objets en attente d'effacement (runtime/secret).
const memLimitShare = 0.85

// noCgroupLimit : au-delà, la valeur lue signifie « pas de limite » (cgroup v1 renvoie ~2^63).
const noCgroupLimit = 1 << 60

// readCgroupLimit renvoie la limite mémoire du conteneur en octets (0 si aucune).
func readCgroupLimit(files []string) int64 {
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- chemins constants
		if err != nil {
			continue
		}
		v, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
		if err != nil || v <= 0 || v >= noCgroupLimit {
			return 0 // "max" ou valeur sans limite effective
		}
		return v
	}
	return 0
}

// configureMemoryLimit pose la cible du ramasse-miettes (GOMEMLIMIT) à memLimitShare de la
// limite du conteneur si l'opérateur ne l'a pas fixée : sans elle, le tas peut doubler entre
// deux collectes et le conteneur être tué (OOM) sous charge. Renvoie la limite effective.
func configureMemoryLimit(files []string) int64 {
	if os.Getenv("GOMEMLIMIT") != "" {
		limit := debug.SetMemoryLimit(-1) // lecture seule
		slog.Info("memory_limit", slog.String("source", "GOMEMLIMIT"), slog.Int64("bytes", limit))
		return limit
	}
	cgroup := readCgroupLimit(files)
	if cgroup == 0 {
		slog.Info("memory_limit", slog.String("source", "none"))
		return 0
	}
	limit := int64(float64(cgroup) * memLimitShare)
	debug.SetMemoryLimit(limit)
	slog.Info("memory_limit", slog.String("source", "cgroup"), slog.Int64("cgroup_bytes", cgroup), slog.Int64("bytes", limit))
	return limit
}

// copiesPerRequest majore le nombre de copies de la charge qu'une requête tient en mémoire au
// pire (corps, chiffré décodé, clair, réponse encodée), mesuré sur /encrypt et /decrypt.
const copiesPerRequest = 4

// warnMemoryBudget signale une configuration dont le pire cas dépasse la mémoire disponible.
func warnMemoryBudget(cfg *config.Config, memLimit int64) {
	if memLimit <= 0 || cfg.MaxConcurrentRequests <= 0 {
		return
	}
	perRequest := api.OpenBodyLimit(cfg.MaxPayloadBytes) + (copiesPerRequest-1)*cfg.MaxPayloadBytes
	worst := int64(cfg.MaxConcurrentRequests) * perRequest
	if worst > memLimit {
		slog.Warn("memory_budget_exceeded",
			slog.Int64("worst_case_bytes", worst),
			slog.Int64("memory_limit_bytes", memLimit),
			slog.String("detail", "réduire MAX_CONCURRENT_REQUESTS ou MAX_PAYLOAD_BYTES, ou augmenter la mémoire du conteneur"))
	}
}
