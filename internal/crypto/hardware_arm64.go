package crypto

import "golang.org/x/sys/cpu"

// HardwareAES indique si AES-GCM s'exécute sur les extensions cryptographiques ARMv8 (AES et PMULL).
func HardwareAES() bool { return cpu.ARM64.HasAES && cpu.ARM64.HasPMULL }
