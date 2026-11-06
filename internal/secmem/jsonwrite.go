package secmem

import (
	"encoding/base64"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// jsonEscapeLen renvoie la taille encodée de l'octet ASCII c dans une chaîne JSON.
// Comme encoding/json : guillemet, barre oblique inverse, caractères de contrôle, et <, >, &
// (échappés pour qu'un JSON inséré dans du HTML ne puisse pas fermer une balise).
func jsonEscapeLen(c byte) int {
	switch {
	case c == '"', c == '\\', c == '\b', c == '\f', c == '\n', c == '\r', c == '\t':
		return 2
	case c < 0x20, c == '<', c == '>', c == '&':
		return 6 // \u00XX
	default:
		return 1
	}
}

// shortEscape renvoie la lettre de l'échappement court (\n, \", ...) d'un octet de taille encodée 2.
func shortEscape(c byte) byte {
	switch c {
	case '\b':
		return 'b'
	case '\f':
		return 'f'
	case '\n':
		return 'n'
	case '\r':
		return 'r'
	case '\t':
		return 't'
	default: // '"' et '\\' s'échappent par eux-mêmes
		return c
	}
}

// JSONStringLen renvoie la taille exacte, guillemets compris, de s encodé en chaîne JSON par
// WriteJSONString. s doit être de l'UTF-8 valide.
func JSONStringLen(s []byte) int {
	n := 2
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			n += jsonEscapeLen(c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(s[i:])
		if r == ' ' || r == ' ' {
			n += 6
		} else {
			n += size
		}
		i += size
	}
	return n
}

// WriteJSONString ajoute s, encodé en chaîne JSON (guillemets compris). s doit être de
// l'UTF-8 valide (à vérifier par l'appelant) : aucune substitution n'est faite.
func (buf *Buffer) WriteJSONString(s []byte) {
	buf.Grow(JSONStringLen(s))
	buf.b = append(buf.b, '"')
	buf.b = appendJSONEscaped(buf.b, s)
	buf.b = append(buf.b, '"')
}

// JSONObject écrit un objet JSON champ par champ dans un Buffer effaçable. Les valeurs secrètes
// (Base64, texte) y sont encodées directement, sans chaîne Go intermédiaire.
type JSONObject struct {
	buf    *Buffer
	fields int
}

// NewJSONObject ouvre un objet JSON dans un tampon de capacité initiale capacity.
func NewJSONObject(capacity int) *JSONObject {
	o := &JSONObject{buf: NewBuffer(capacity)}
	_ = o.buf.WriteByte('{')
	return o
}

func (o *JSONObject) key(name string) {
	if o.fields > 0 {
		_ = o.buf.WriteByte(',')
	}
	o.fields++
	o.buf.WriteJSONString([]byte(name))
	_ = o.buf.WriteByte(':')
}

// String ajoute un champ chaîne (valeur non secrète, UTF-8 valide).
func (o *JSONObject) String(name, value string) {
	o.key(name)
	o.buf.WriteJSONString([]byte(value))
}

// StringOmitEmpty ajoute le champ seulement si value n'est pas vide.
func (o *JSONObject) StringOmitEmpty(name, value string) {
	if value != "" {
		o.String(name, value)
	}
}

// Text ajoute un champ chaîne dont la valeur, éventuellement secrète, est déjà de l'UTF-8 valide.
func (o *JSONObject) Text(name string, value []byte) {
	o.key(name)
	o.buf.WriteJSONString(value)
}

// Base64 ajoute un champ dont la valeur est l'encodage Base64 standard de value.
func (o *JSONObject) Base64(name string, value []byte) {
	o.key(name)
	o.buf.Grow(base64.StdEncoding.EncodedLen(len(value)) + 2)
	_ = o.buf.WriteByte('"')
	o.buf.WriteBase64(value)
	_ = o.buf.WriteByte('"')
}

// Uint ajoute un champ entier non signé.
func (o *JSONObject) Uint(name string, v uint64) {
	o.key(name)
	o.buf.WriteUint(v)
}

// UintOmitZero ajoute le champ seulement si v n'est pas nul.
func (o *JSONObject) UintOmitZero(name string, v uint64) {
	if v != 0 {
		o.Uint(name, v)
	}
}

// Int ajoute un champ entier signé.
func (o *JSONObject) Int(name string, v int64) {
	o.key(name)
	o.buf.WriteInt(v)
}

// OpenField écrit « ,"name": » (sans valeur) et renvoie le tampon : l'appelant écrit la
// valeur puis la fin de l'objet lui-même, en flux.
func (o *JSONObject) OpenField(name string) *Buffer {
	o.key(name)
	return o.buf
}

// Finish ferme l'objet et renvoie le tampon, que l'appelant efface (Wipe) après usage.
func (o *JSONObject) Finish() *Buffer {
	_ = o.buf.WriteByte('}')
	return o.buf
}

// FinishLine ferme l'objet suivi d'un saut de ligne, comme json.Encoder (corps de réponse HTTP).
func (o *JSONObject) FinishLine() *Buffer {
	_ = o.buf.WriteByte('}')
	_ = o.buf.WriteByte('\n')
	return o.buf
}
