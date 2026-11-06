//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"pq-crypto-service/internal/secmem"
)

// scrubEnviron écrase, dans le bloc d'environnement initial du processus (celui que le
// noyau expose dans /proc/<pid>/environ), la valeur des variables nommées. os.Unsetenv ne
// modifie que la copie du runtime Go : sans cela, un secret passé par l'environnement reste
// lisible par tout processus autorisé à lire /proc/<pid>/environ pendant toute la vie du
// service. À appeler avant HardenProcess (PR_SET_DUMPABLE=0 rend /proc/self/mem inaccessible).
func scrubEnviron(names ...string) error {
	start, end, err := environRange()
	if err != nil {
		return err
	}
	mem, err := os.OpenFile("/proc/self/mem", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("ouverture de /proc/self/mem: %w", err)
	}
	defer mem.Close()

	block := make([]byte, end-start)
	// La copie de travail contient l'environnement entier, secrets compris : elle est effacée
	// au retour, sinon elle survivrait dans le tas à l'effacement qu'elle sert à réaliser.
	defer secmem.Wipe(block)
	if _, err := mem.ReadAt(block, int64(start)); err != nil { // #nosec G115 -- adresse du noyau
		return fmt.Errorf("lecture du bloc d'environnement: %w", err)
	}
	for pos := 0; pos < len(block); {
		next := bytes.IndexByte(block[pos:], 0)
		if next < 0 {
			next = len(block) - pos
		}
		entry := block[pos : pos+next]
		for _, name := range names {
			if !bytes.HasPrefix(entry, []byte(name+"=")) {
				continue
			}
			value := entry[len(name)+1:]
			if len(value) == 0 {
				continue
			}
			offset := int64(start) + int64(pos+len(name)+1) // #nosec G115 -- adresse fournie par le noyau
			if _, err := mem.WriteAt(make([]byte, len(value)), offset); err != nil {
				return fmt.Errorf("effacement de %s dans l'environnement initial: %w", name, err)
			}
		}
		pos += next + 1
	}
	return nil
}

// environRange lit env_start et env_end dans /proc/self/stat (champs 50 et 51, man proc(5)).
func environRange() (start, end uint64, err error) {
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0, err
	}
	// Le nom de commande (champ 2) peut contenir des espaces : repartir de la parenthèse fermante.
	rest := string(stat[bytes.LastIndexByte(stat, ')')+2:])
	fields := strings.Fields(rest) // fields[0] est le champ 3 (state)
	if len(fields) < 49 {
		return 0, 0, fmt.Errorf("/proc/self/stat : %d champs, env_start absent", len(fields)+2)
	}
	if start, err = strconv.ParseUint(fields[47], 10, 64); err != nil {
		return 0, 0, err
	}
	if end, err = strconv.ParseUint(fields[48], 10, 64); err != nil {
		return 0, 0, err
	}
	if end < start || end-start > 1<<24 {
		return 0, 0, fmt.Errorf("plage d'environnement incohérente")
	}
	return start, end, nil
}
