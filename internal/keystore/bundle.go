package keystore

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"pq-crypto-service/internal/secmem"
)

// ErrCorruptedBundle signale un bundle illisible, d'une autre version ou dont le checksum
// ne correspond pas : la paire n'est jamais chargée ni remplacée dans ce cas.
var ErrCorruptedBundle = errors.New("bundle de clés corrompu ou invalide")

// BundleFormatVersion est la version du format de bundle écrit par le service.
const BundleFormatVersion = 1

// KeypairBundle documente le format (version 1) de la paire stockée dans un coffre.
//
// Le format est le même pour tous les coffres (Infisical, OpenBao) : un bundle se migre d'un
// coffre à l'autre par simple copie de ses champs, sans passer par le service. Le code ne
// l'utilise pas pour lire la clé privée : voir BundleWire.
type KeypairBundle struct {
	FormatVersion int    `json:"format_version"`
	Algorithm     string `json:"algorithm"`
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
	CreatedAt     string `json:"created_at"`
	Checksum      string `json:"checksum"`
}

// BundleWire lit un KeypairBundle sans jamais placer la clé privée dans une chaîne Go.
// Le propriétaire appelle Wipe une fois les clés extraites.
type BundleWire struct {
	FormatVersion int         `json:"format_version"`
	Algorithm     string      `json:"algorithm"`
	PublicKey     string      `json:"public_key"`
	PrivateKey    secmem.Text `json:"private_key"`
	CreatedAt     string      `json:"created_at"`
	Checksum      string      `json:"checksum"`
}

// Wipe efface la clé privée encodée.
func (b *BundleWire) Wipe() { b.PrivateKey.Wipe() }

// keypairChecksum renvoie SHA-256(pubB64 ":" privB64), qui détecte une corruption du bundle.
func keypairChecksum(pubB64 string, privB64 []byte) []byte {
	h := sha256.New()
	h.Write([]byte(pubB64))
	h.Write([]byte{':'})
	h.Write(privB64)
	return h.Sum(nil)
}

// Keys vérifie le bundle (version, algorithme, checksum) et renvoie la paire décodée.
// sk est décodée directement dans un tampon possédé, que l'appelant efface. algorithm vide :
// l'algorithme du bundle n'est pas vérifié.
func (b *BundleWire) Keys(algorithm string) (pk, sk []byte, err error) {
	if b.FormatVersion != BundleFormatVersion {
		return nil, nil, fmt.Errorf("%w: version %d", ErrCorruptedBundle, b.FormatVersion)
	}
	if b.Algorithm != "" && algorithm != "" && !strings.EqualFold(b.Algorithm, algorithm) {
		return nil, nil, fmt.Errorf("%w: algo '%s' incompatible avec cfg '%s'", ErrCorruptedBundle, b.Algorithm, algorithm)
	}
	want, err := hex.DecodeString(b.Checksum)
	if err != nil || subtle.ConstantTimeCompare(want, keypairChecksum(b.PublicKey, b.PrivateKey)) != 1 {
		return nil, nil, fmt.Errorf("%w: corruption détectée (checksum mismatch)", ErrCorruptedBundle)
	}

	pk, err = base64.StdEncoding.DecodeString(b.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: clé publique Base64 invalide", ErrCorruptedBundle)
	}
	sk = make([]byte, base64.StdEncoding.DecodedLen(len(b.PrivateKey)))
	n, err := base64.StdEncoding.Decode(sk, b.PrivateKey)
	if err != nil {
		secmem.Wipe(sk)
		return nil, nil, fmt.Errorf("%w: clé privée Base64 invalide", ErrCorruptedBundle)
	}
	return pk, sk[:n], nil
}

// ParseBundle décode un bundle JSON brut puis le vérifie (voir BundleWire.Keys).
func ParseBundle(raw []byte, algorithm string) (pk, sk []byte, err error) {
	var b BundleWire
	defer b.Wipe()
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, nil, fmt.Errorf("%w: JSON illisible", ErrCorruptedBundle)
	}
	return b.Keys(algorithm)
}

// EncodeBundle sérialise la paire au format bundle dans un tampon effaçable, que l'appelant
// efface (Wipe). La clé privée n'est encodée que dans des tampons effaçables.
func EncodeBundle(algorithm string, pk, sk []byte, createdAt time.Time) *secmem.Buffer {
	pubB64 := base64.StdEncoding.EncodeToString(pk)
	privB64 := secmem.NewBuffer(base64.StdEncoding.EncodedLen(len(sk)))
	defer privB64.Wipe()
	privB64.WriteBase64(sk)

	o := secmem.NewJSONObject(256 + len(pubB64) + privB64.Len() + len(algorithm))
	o.Int("format_version", BundleFormatVersion)
	o.String("algorithm", algorithm)
	o.String("public_key", pubB64)
	o.Text("private_key", privB64.Bytes())
	o.String("created_at", createdAt.UTC().Format(time.RFC3339))
	o.String("checksum", hex.EncodeToString(keypairChecksum(pubB64, privB64.Bytes())))
	return o.Finish()
}
