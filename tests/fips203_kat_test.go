package tests

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/schemes"
)

// HexBytes décode automatiquement une chaîne hexadécimale JSON en []byte.
type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	clean := strings.TrimPrefix(s, "0x")
	decoded, err := hex.DecodeString(clean)
	if err != nil {
		return err
	}
	*h = decoded
	return nil
}

// acvpData stocke les vecteurs d'entrée (prompt) et de sortie attendue (expectedResults).
type acvpData struct {
	Groups  []json.RawMessage
	results map[int]json.RawMessage
}

// loadACVP décompresse et charge les fichiers JSON NIST ACVP du répertoire spécifié.
func loadACVP(t *testing.T, dir string) *acvpData {
	t.Helper()

	promptPath := filepath.Join(dir, "prompt.json.gz")
	promptBytes, err := readGzFile(promptPath)
	if err != nil {
		t.Fatalf("Impossible de lire %s: %v", promptPath, err)
	}

	var promptFile struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}
	if err := json.Unmarshal(promptBytes, &promptFile); err != nil {
		t.Fatalf("Erreur unmarshal prompt %s: %v", promptPath, err)
	}

	resultsPath := filepath.Join(dir, "expectedResults.json.gz")
	resultsBytes, err := readGzFile(resultsPath)
	if err != nil {
		t.Fatalf("Impossible de lire %s: %v", resultsPath, err)
	}

	var resultsFile struct {
		TestGroups []struct {
			Tests []json.RawMessage `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(resultsBytes, &resultsFile); err != nil {
		t.Fatalf("Erreur unmarshal results %s: %v", resultsPath, err)
	}

	resMap := make(map[int]json.RawMessage)
	for _, group := range resultsFile.TestGroups {
		for _, rawTest := range group.Tests {
			var testMeta struct {
				TcID int `json:"tcId"`
			}
			if err := json.Unmarshal(rawTest, &testMeta); err != nil {
				t.Fatalf("Erreur lecture tcId: %v", err)
			}
			resMap[testMeta.TcID] = rawTest
		}
	}

	return &acvpData{
		Groups:  promptFile.TestGroups,
		results: resMap,
	}
}

func readGzFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	return io.ReadAll(gz)
}

// =============================================================================
// TESTS OFFICIELS NIST FIPS 203 (ACVP - KNOWN ANSWER TESTS)
// =============================================================================

// TestKAT_NIST_FIPS203_KeyGen valide de manière exhaustive la génération de paires
// de clés (KeyGen AFT) à partir des graines NIST officielles (d || z).
func TestKAT_NIST_FIPS203_KeyGen(t *testing.T) {
	data := loadACVP(t, filepath.Join("testdata", "ML-KEM-keyGen-FIPS203"))
	totalTests := 0

	for _, rawGroup := range data.Groups {
		var group struct {
			TestType     string `json:"testType"`
			ParameterSet string `json:"parameterSet"`
			Tests        []struct {
				TcID int      `json:"tcId"`
				Z    HexBytes `json:"z"`
				D    HexBytes `json:"d"`
			} `json:"tests"`
		}
		if err := json.Unmarshal(rawGroup, &group); err != nil {
			t.Fatalf("Erreur unmarshal group keyGen: %v", err)
		}

		if group.TestType != "AFT" {
			continue
		}

		scheme := schemes.ByName(group.ParameterSet)
		if scheme == nil {
			t.Fatalf("Schéma NIST non supporté: %s", group.ParameterSet)
		}

		groupTests := 0
		for _, tc := range group.Tests {
			rawRes, ok := data.results[tc.TcID]
			if !ok {
				t.Fatalf("Résultat manquant pour tcId=%d (%s)", tc.TcID, group.ParameterSet)
			}

			var res struct {
				Ek HexBytes `json:"ek"`
				Dk HexBytes `json:"dk"`
			}
			if err := json.Unmarshal(rawRes, &res); err != nil {
				t.Fatalf("Erreur unmarshal resultat tcId=%d: %v", tc.TcID, err)
			}

			// Graine déterministe NIST FIPS 203 : d (32B) || z (32B)
			if len(tc.D) != 32 || len(tc.Z) != 32 {
				t.Fatalf("tcId=%d: graine invalide d=%d z=%d", tc.TcID, len(tc.D), len(tc.Z))
			}
			var seed [64]byte
			copy(seed[:32], tc.D)
			copy(seed[32:], tc.Z)

			ek, dk := scheme.DeriveKeyPair(seed[:])

			// Sérialisation binaire et comparaison stricte au bit près
			ekBytes, err := ek.MarshalBinary()
			if err != nil {
				t.Fatalf("tcId=%d: erreur marshal public key: %v", tc.TcID, err)
			}
			dkBytes, err := dk.MarshalBinary()
			if err != nil {
				t.Fatalf("tcId=%d: erreur marshal private key: %v", tc.TcID, err)
			}

			if !bytes.Equal(ekBytes, res.Ek) {
				t.Fatalf("tcId=%d (%s): non-conformité clé publique ek !\nObtenu:  %x\nAttendu: %x", tc.TcID, group.ParameterSet, ekBytes, res.Ek)
			}
			if !bytes.Equal(dkBytes, res.Dk) {
				t.Fatalf("tcId=%d (%s): non-conformité clé privée dk !\nObtenu:  %x\nAttendu: %x", tc.TcID, group.ParameterSet, dkBytes, res.Dk)
			}

			groupTests++
			totalTests++
		}
		if groupTests != 25 {
			t.Fatalf("KAT KeyGen pour %s incomplet: %d/25", group.ParameterSet, groupTests)
		}
		t.Logf("✅ NIST FIPS 203 KeyGen [%s]: %d vecteurs validés avec succès au bit près", group.ParameterSet, groupTests)
	}

	if totalTests != 75 {
		t.Fatalf("KAT KeyGen total incomplet : %d/75", totalTests)
	}
	t.Logf("Total tests KeyGen NIST FIPS 203 validés : %d", totalTests)
}

// TestKAT_NIST_FIPS203_EncapDecap valide de manière exhaustive l'encapsulation déterministe (AFT)
// et la décapsulation (VAL) contre l'intégralité des vecteurs de test officiels du NIST.
func TestKAT_NIST_FIPS203_EncapDecap(t *testing.T) {
	data := loadACVP(t, filepath.Join("testdata", "ML-KEM-encapDecap-FIPS203"))
	totalEncap := 0
	totalDecap := 0

	for _, rawGroup := range data.Groups {
		var metaGroup struct {
			TestType     string `json:"testType"`
			ParameterSet string `json:"parameterSet"`
		}
		if err := json.Unmarshal(rawGroup, &metaGroup); err != nil {
			t.Fatalf("Erreur unmarshal meta group: %v", err)
		}

		scheme := schemes.ByName(metaGroup.ParameterSet)
		if scheme == nil {
			t.Fatalf("Schéma NIST non supporté: %s", metaGroup.ParameterSet)
		}

		switch metaGroup.TestType {
		case "AFT":
			// Test d'encapsulation déterministe avec graine m
			var group struct {
				ParameterSet string `json:"parameterSet"`
				Tests        []struct {
					TcID int      `json:"tcId"`
					Ek   HexBytes `json:"ek"`
					M    HexBytes `json:"m"`
				} `json:"tests"`
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatalf("Erreur unmarshal group encap AFT: %v", err)
			}

			aftCount := 0
			for _, tc := range group.Tests {
				rawRes, ok := data.results[tc.TcID]
				if !ok {
					t.Fatalf("Résultat manquant tcId=%d", tc.TcID)
				}
				var res struct {
					C HexBytes `json:"c"`
					K HexBytes `json:"k"`
				}
				if err := json.Unmarshal(rawRes, &res); err != nil {
					t.Fatalf("Erreur unmarshal res tcId=%d: %v", tc.TcID, err)
				}

				ek, err := scheme.UnmarshalBinaryPublicKey(tc.Ek)
				if err != nil {
					t.Fatalf("tcId=%d: unmarshal public key: %v", tc.TcID, err)
				}

				ct, ss, err := scheme.EncapsulateDeterministically(ek, tc.M)
				if err != nil {
					t.Fatalf("tcId=%d: encapsulation déterministe: %v", tc.TcID, err)
				}

				if !bytes.Equal(ct, res.C) {
					t.Fatalf("tcId=%d (%s): ciphertext non conforme !\nObtenu:  %x\nAttendu: %x", tc.TcID, group.ParameterSet, ct, res.C)
				}
				if !bytes.Equal(ss, res.K) {
					t.Fatalf("tcId=%d (%s): secret partagé non conforme !\nObtenu:  %x\nAttendu: %x", tc.TcID, group.ParameterSet, ss, res.K)
				}

				aftCount++
				totalEncap++
			}
			if aftCount != 25 {
				t.Fatalf("KAT Encap AFT pour %s incomplet: %d/25", group.ParameterSet, aftCount)
			}
			t.Logf("✅ NIST FIPS 203 Encap AFT [%s]: %d vecteurs validés avec succès", group.ParameterSet, aftCount)

		case "VAL":
			// Test de décapsulation de ciphertext
			var group struct {
				ParameterSet string   `json:"parameterSet"`
				Dk           HexBytes `json:"dk"`
				Tests        []struct {
					TcID int      `json:"tcId"`
					C    HexBytes `json:"c"`
				} `json:"tests"`
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatalf("Erreur unmarshal group decap VAL: %v", err)
			}

			dk, err := scheme.UnmarshalBinaryPrivateKey(group.Dk)
			if err != nil {
				t.Fatalf("unmarshal private key: %v", err)
			}

			valCount := 0
			for _, tc := range group.Tests {
				rawRes, ok := data.results[tc.TcID]
				if !ok {
					t.Fatalf("Résultat manquant tcId=%d", tc.TcID)
				}
				var res struct {
					K HexBytes `json:"k"`
				}
				if err := json.Unmarshal(rawRes, &res); err != nil {
					t.Fatalf("Erreur unmarshal res tcId=%d: %v", tc.TcID, err)
				}

				ss, err := scheme.Decapsulate(dk, tc.C)
				if err != nil {
					t.Fatalf("tcId=%d: décapsulation: %v", tc.TcID, err)
				}

				if !bytes.Equal(ss, res.K) {
					t.Fatalf("tcId=%d (%s): secret décapsulé non conforme !\nObtenu:  %x\nAttendu: %x", tc.TcID, group.ParameterSet, ss, res.K)
				}

				valCount++
				totalDecap++
			}
			if valCount != 10 {
				t.Fatalf("KAT Decap VAL pour %s incomplet: %d/10", group.ParameterSet, valCount)
			}
			t.Logf("✅ NIST FIPS 203 Decap VAL [%s]: %d vecteurs validés avec succès", group.ParameterSet, valCount)
		}
	}

	if totalEncap != 75 {
		t.Fatalf("KAT Encap total incomplet : %d/75", totalEncap)
	}
	if totalDecap != 30 {
		t.Fatalf("KAT Decap total incomplet : %d/30", totalDecap)
	}
	t.Logf("Total tests Encap NIST FIPS 203 validés : %d", totalEncap)
	t.Logf("Total tests Decap NIST FIPS 203 validés : %d", totalDecap)
}

// TestKAT_NIST_FIPS203_MonteCarlo_StressTest exécute 1000 itérations séquentielles enchaînées
// de dérivation de clé, encapsulation déterministe, décapsulation et validation d'intégrité,
// selon le modèle des tests de stress Monte-Carlo du NIST CAVP/ACVP.
func TestKAT_NIST_FIPS203_MonteCarlo_StressTest(t *testing.T) {
	for _, paramSet := range []string{"ML-KEM-768", "ML-KEM-1024"} {
		t.Run(paramSet, func(t *testing.T) {
			scheme := schemes.ByName(paramSet)
			if scheme == nil {
				t.Fatalf("Schéma non supporté: %s", paramSet)
			}

			// Graine initiale déterministe
			seed := sha256.Sum256([]byte("NIST-FIPS-203-MONTE-CARLO-INIT-" + paramSet))
			const iterations = 1000

			for i := 0; i < iterations; i++ {
				// 1. Dérivation déterministe de la paire de clés (d || z)
				var keySeed [64]byte
				h1 := sha256.Sum256(append(seed[:], 0x01))
				h2 := sha256.Sum256(append(seed[:], 0x02))
				copy(keySeed[:32], h1[:])
				copy(keySeed[32:], h2[:])

				ek, dk := scheme.DeriveKeyPair(keySeed[:])

				// 2. Encapsulation déterministe avec graine m
				mSeed := sha256.Sum256(append(seed[:], 0x03))
				ct, ssEncap, err := scheme.EncapsulateDeterministically(ek, mSeed[:])
				if err != nil {
					t.Fatalf("itération %d: échec encapsulation: %v", i, err)
				}

				// 3. Décapsulation
				ssDecap, err := scheme.Decapsulate(dk, ct)
				if err != nil {
					t.Fatalf("itération %d: échec décapsulation: %v", i, err)
				}

				// 4. Validation stricte en temps constant du secret partagé
				if subtle.ConstantTimeCompare(ssEncap, ssDecap) != 1 {
					t.Fatalf("itération %d: désaccord entre encapsulation et décapsulation", i)
				}

				// 5. Mise à jour de la graine (Monte-Carlo feedback chain)
				hUpdate := sha256.New()
				hUpdate.Write(seed[:])
				hUpdate.Write(ct)
				hUpdate.Write(ssEncap)
				copy(seed[:], hUpdate.Sum(nil))
			}

			finalHash := hex.EncodeToString(seed[:])
			expectedHashes := map[string]string{
				"ML-KEM-768":  "b27f9cc4ad8df39434061c550d024262c4e176dca8a2fd16fee4f41489769779",
				"ML-KEM-1024": "2b13db7cc96efde0027346c91459cd9ea7652bb8a7b746047d671525425feaf7",
			}
			if expected, ok := expectedHashes[paramSet]; ok && finalHash != expected {
				t.Fatalf("Rupture de reproductibilité Monte-Carlo [%s] !\nAttendu: %s\nObtenu:  %s", paramSet, expected, finalHash)
			}
			t.Logf("✅ Monte-Carlo [%s]: %d itérations consécutives validées au bit près (Accumulator SHA-256: %s)", paramSet, iterations, finalHash)
		})
	}
}
