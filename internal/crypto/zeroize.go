package crypto

import "pq-crypto-service/internal/secmem"

// Zeroize écrase b avec des zéros (voir secmem.Wipe). Elle n'atteint pas les copies de b
// faites ailleurs ; l'effacement des temporaires internes (pile, registres, tas des
// bibliothèques) relève de withSecretErasure.
func Zeroize(b []byte) { secmem.Wipe(b) }
