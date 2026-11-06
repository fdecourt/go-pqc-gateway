package crypto

import "golang.org/x/sys/cpu"

// HardwareAES indique si AES-GCM s'exécute sur des instructions dédiées (AES-NI et PCLMULQDQ),
// seule configuration où l'implémentation de Go est en temps constant.
func HardwareAES() bool { return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ }
