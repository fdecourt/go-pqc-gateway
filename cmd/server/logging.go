package main

import (
	"log/slog"
	"os"

	"pq-crypto-service/internal/config"
)

// setupLogging installe le journal structuré du service. slog.SetDefault redirige aussi
// le paquet log standard (dépendances) vers ce handler : la sortie reste homogène.
func setupLogging(cfg *config.Config) {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}
