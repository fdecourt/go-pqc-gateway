package secmem

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// Erreurs de DecodeStrict. Leurs messages ne citent jamais une valeur : seuls des noms de champs.
var (
	ErrInvalidJSON   = errors.New("JSON syntaxiquement invalide")
	ErrNotObject     = errors.New("un objet JSON est attendu")
	ErrInvalidBase64 = errors.New("valeur Base64 invalide (encodage standard RFC 4648, remplissage canonique)")
	ErrInvalidUTF8   = errors.New("chaîne UTF-8 invalide")
	ErrNestedValue   = errors.New("valeur imbriquée (objet ou tableau) non admise")
)

// Base64 est un champ JSON chaîne contenant du Base64 standard, décodé à la lecture.
//
// Le décodage est strict (remplissage et bits de bourrage canoniques) : une même valeur n'a
// qu'une représentation. Une valeur JSON null laisse le champ vide.
type Base64 []byte

// UnmarshalText implémente encoding.TextUnmarshaler (lecture par encoding/json, hors DecodeStrict).
// Le texte source est effacé après décodage : c'est une copie de la valeur, aussi sensible qu'elle.
func (b *Base64) UnmarshalText(text []byte) error {
	defer Wipe(text)
	out, err := decodeBase64Strict(text)
	if err != nil {
		return err
	}
	*b = out
	return nil
}

// Wipe efface la valeur décodée.
func (b *Base64) Wipe() { Wipe(*b); *b = nil }

// Text est un champ JSON chaîne lu comme octets UTF-8 effaçables, au lieu d'une chaîne Go immuable.
type Text []byte

// UnmarshalText implémente encoding.TextUnmarshaler (lecture par encoding/json, hors DecodeStrict).
func (t *Text) UnmarshalText(text []byte) error {
	defer Wipe(text)
	if !utf8.Valid(text) {
		return ErrInvalidUTF8
	}
	*t = append([]byte(nil), text...)
	return nil
}

// Wipe efface la valeur.
func (t *Text) Wipe() { Wipe(*t); *t = nil }

// decodeBase64Strict décode text dans un tampon neuf, avec TailSlack de capacité en plus
// (chiffrement en place possible sans réallocation).
func decodeBase64Strict(text []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(text)), base64.StdEncoding.DecodedLen(len(text))+TailSlack)
	n, err := base64.StdEncoding.Strict().Decode(out, text)
	if err != nil {
		Wipe(out)
		return nil, ErrInvalidBase64
	}
	return out[:n], nil
}

// DecodeStrict décode l'objet JSON plat data dans dst (pointeur vers une structure), en une
// seule passe et sans copie des valeurs secrètes autre que la leur :
//   - un seul objet au niveau supérieur, rien après ; aucune valeur imbriquée ;
//   - chaque clé doit correspondre exactement (casse comprise) à un champ déclaré de dst
//     (étiquettes json, champs anonymes aplatis), une seule fois : pas de clé inconnue,
//     dupliquée ou échappée, qui pourrait être lue différemment par un autre analyseur ;
//   - les chaînes doivent être de l'UTF-8 valide, sans demi-paire de substitution ;
//   - un entier n'admet ni fraction ni exposant ;
//   - un corps vide ou composé d'espaces est refusé, sauf si allowEmpty.
//
// Champs admis : string, bool, entiers (signés ou non), Base64 et Text. data appartient à
// l'appelant, qui l'efface après l'appel. Les messages d'erreur ne contiennent aucune valeur.
func DecodeStrict(data []byte, dst any, allowEmpty bool) error {
	p := parser{data: data}
	p.skipSpace()
	if p.eof() {
		if allowEmpty {
			return nil
		}
		return ErrInvalidJSON
	}
	if p.data[p.i] != '{' {
		return ErrNotObject
	}
	p.i++

	fields := structFields(reflect.TypeOf(dst))
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return errors.New("DecodeStrict : destination non pointeur de structure")
	}
	v = v.Elem()
	seen := make(map[string]struct{}, len(fields))

	p.skipSpace()
	if !p.eof() && p.data[p.i] == '}' {
		p.i++
		return p.trailing()
	}
	for {
		p.skipSpace()
		if p.eof() || p.data[p.i] != '"' {
			return ErrInvalidJSON
		}
		key, escaped, err := p.rawString()
		if err != nil {
			return err
		}
		if escaped {
			return errors.New("clé JSON échappée non admise")
		}
		f, ok := fields[string(key)]
		if !ok {
			return fmt.Errorf("champ inconnu %q", truncateKey(string(key)))
		}
		if _, dup := seen[f.name]; dup {
			return fmt.Errorf("champ %q présent plusieurs fois", f.name)
		}
		seen[f.name] = struct{}{}

		p.skipSpace()
		if p.eof() || p.data[p.i] != ':' {
			return ErrInvalidJSON
		}
		p.i++
		p.skipSpace()
		if err := p.value(f, v.FieldByIndex(f.index)); err != nil {
			return err
		}

		p.skipSpace()
		if p.eof() {
			return ErrInvalidJSON
		}
		switch p.data[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return p.trailing()
		default:
			return ErrInvalidJSON
		}
	}
}

type parser struct {
	data []byte
	i    int
}

func (p *parser) eof() bool { return p.i >= len(p.data) }

func (p *parser) skipSpace() {
	for p.i < len(p.data) {
		switch p.data[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// trailing vérifie qu'il ne reste que des espaces après l'objet.
func (p *parser) trailing() error {
	p.skipSpace()
	if !p.eof() {
		return errors.New("données après la fin de l'objet JSON")
	}
	return nil
}

// rawString lit une chaîne JSON à partir du guillemet ouvrant et renvoie son contenu brut
// (entre guillemets, échappements non résolus) et s'il contient des échappements.
// Les octets de contrôle sont refusés, comme le veut la grammaire JSON.
func (p *parser) rawString() ([]byte, bool, error) {
	start := p.i + 1
	escaped := false
	i := start
	for {
		// Chemin rapide : jusqu'au prochain guillemet ou antislash (recherche vectorisée).
		q := bytes.IndexByte(p.data[i:], '"')
		if q < 0 {
			return nil, false, ErrInvalidJSON
		}
		seg := p.data[i : i+q]
		if b := bytes.IndexByte(seg, '\\'); b >= 0 {
			if hasControlByte(seg[:b]) || i+b+1 >= len(p.data) {
				return nil, false, ErrInvalidJSON
			}
			escaped = true
			i += b + 2 // l'octet suivant fait partie de l'échappement
			continue
		}
		if hasControlByte(seg) {
			return nil, false, ErrInvalidJSON
		}
		p.i = i + q + 1
		return p.data[start : i+q], escaped, nil
	}
}

// hasControlByte indique si b contient un octet < 0x20, par mots de 8 octets.
func hasControlByte(b []byte) bool {
	const (
		ones = 0x0101010101010101
		high = 0x8080808080808080
	)
	for len(b) >= 8 {
		x := binary.LittleEndian.Uint64(b)
		// Un octet < 0x20 produit un emprunt dans (x - 0x20·ones) sans bit haut dans x.
		if (x-0x20*ones)&^x&high != 0 {
			return true
		}
		b = b[8:]
	}
	for _, c := range b {
		if c < 0x20 {
			return true
		}
	}
	return false
}

// stringValue lit une chaîne et renvoie ses octets décodés. owned indique si le tampon
// renvoyé a été alloué (échappements résolus) ou pointe dans data.
func (p *parser) stringValue() (val []byte, owned bool, err error) {
	raw, escaped, err := p.rawString()
	if err != nil {
		return nil, false, err
	}
	if !escaped {
		return raw, false, nil // validité UTF-8 vérifiée par setString selon le type du champ
	}
	out, err := unescape(raw)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// unescape résout les échappements JSON dans un tampon neuf, en refusant tout échappement
// invalide, toute demi-paire de substitution et tout octet UTF-8 invalide.
func unescape(raw []byte) ([]byte, error) {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		c := raw[i]
		if c != '\\' {
			if c < utf8.RuneSelf {
				out = append(out, c)
				i++
				continue
			}
			r, size := utf8.DecodeRune(raw[i:])
			if r == utf8.RuneError && size == 1 {
				Wipe(out)
				return nil, ErrInvalidUTF8
			}
			out = append(out, raw[i:i+size]...)
			i += size
			continue
		}
		if i+1 >= len(raw) {
			Wipe(out)
			return nil, ErrInvalidJSON
		}
		switch raw[i+1] {
		case '"', '\\', '/':
			out = append(out, raw[i+1])
			i += 2
		case 'b':
			out = append(out, '\b')
			i += 2
		case 'f':
			out = append(out, '\f')
			i += 2
		case 'n':
			out = append(out, '\n')
			i += 2
		case 'r':
			out = append(out, '\r')
			i += 2
		case 't':
			out = append(out, '\t')
			i += 2
		case 'u':
			r, n, ok := hexRune(raw[i:])
			if !ok {
				Wipe(out)
				return nil, ErrInvalidJSON
			}
			i += n
			if utf16.IsSurrogate(r) {
				r2, n2, ok := hexRune(raw[i:])
				if !ok {
					Wipe(out)
					return nil, ErrInvalidUTF8
				}
				r = utf16.DecodeRune(r, r2)
				if r == utf8.RuneError {
					Wipe(out)
					return nil, ErrInvalidUTF8
				}
				i += n2
			}
			out = utf8.AppendRune(out, r)
		default:
			Wipe(out)
			return nil, ErrInvalidJSON
		}
	}
	return out, nil
}

// hexRune lit « \uXXXX » en tête de b.
func hexRune(b []byte) (r rune, n int, ok bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, 0, false
	}
	for _, c := range b[2:6] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, 0, false
		}
		r = r<<4 | rune(d)
	}
	return r, 6, true
}

// literal consomme un littéral attendu (true, false, null).
func (p *parser) literal(s string) bool {
	if bytes.HasPrefix(p.data[p.i:], []byte(s)) {
		p.i += len(s)
		return true
	}
	return false
}

// number lit un entier JSON strict : -?(0|[1-9][0-9]*), sans fraction ni exposant.
func (p *parser) number() ([]byte, error) {
	start := p.i
	if p.i < len(p.data) && p.data[p.i] == '-' {
		p.i++
	}
	if p.eof() {
		return nil, ErrInvalidJSON
	}
	switch {
	case p.data[p.i] == '0':
		p.i++
	case p.data[p.i] >= '1' && p.data[p.i] <= '9':
		for p.i < len(p.data) && p.data[p.i] >= '0' && p.data[p.i] <= '9' {
			p.i++
		}
	default:
		return nil, ErrInvalidJSON
	}
	if p.i < len(p.data) {
		switch p.data[p.i] {
		case '.', 'e', 'E':
			return nil, errors.New("nombre entier attendu (ni fraction ni exposant)")
		}
	}
	return p.data[start:p.i], nil
}

// value lit la valeur du champ f et l'affecte à fv.
func (p *parser) value(f *fieldInfo, fv reflect.Value) error {
	if p.eof() {
		return ErrInvalidJSON
	}
	switch c := p.data[p.i]; {
	case c == 'n':
		if !p.literal("null") {
			return ErrInvalidJSON
		}
		return nil // null laisse la valeur zéro
	case c == '"':
		val, owned, err := p.stringValue()
		if err != nil {
			return err
		}
		return setString(f, fv, val, owned)
	case c == 't' || c == 'f':
		lit := "true"
		if c == 'f' {
			lit = "false"
		}
		if !p.literal(lit) {
			return ErrInvalidJSON
		}
		if f.kind != kindBool {
			return fmt.Errorf("champ %q : type %s attendu", f.name, f.typeName)
		}
		fv.SetBool(lit == "true")
		return nil
	case c == '-' || (c >= '0' && c <= '9'):
		num, err := p.number()
		if err != nil {
			return err
		}
		return setNumber(f, fv, num)
	case c == '{' || c == '[':
		return ErrNestedValue
	default:
		return ErrInvalidJSON
	}
}

func setString(f *fieldInfo, fv reflect.Value, val []byte, owned bool) error {
	switch f.kind {
	case kindBase64:
		out, err := decodeBase64Strict(val)
		Wipe(val) // le texte source est une copie du secret, qu'il pointe dans data ou non
		if err != nil {
			return err
		}
		fv.SetBytes(out)
		return nil
	case kindText:
		if !owned {
			if !utf8.Valid(val) {
				return ErrInvalidUTF8
			}
			copied := append([]byte(nil), val...)
			Wipe(val)
			val = copied
		}
		fv.SetBytes(val)
		return nil
	case kindString:
		if !owned && !utf8.Valid(val) {
			return ErrInvalidUTF8
		}
		fv.SetString(string(val))
		if owned {
			Wipe(val)
		}
		return nil
	default:
		if owned {
			Wipe(val)
		}
		return fmt.Errorf("champ %q : type %s attendu", f.name, f.typeName)
	}
}

func setNumber(f *fieldInfo, fv reflect.Value, num []byte) error {
	switch f.kind {
	case kindInt:
		n, err := strconv.ParseInt(string(num), 10, fv.Type().Bits())
		if err != nil {
			return fmt.Errorf("champ %q : entier hors bornes", f.name)
		}
		fv.SetInt(n)
		return nil
	case kindUint:
		n, err := strconv.ParseUint(string(num), 10, fv.Type().Bits())
		if err != nil {
			return fmt.Errorf("champ %q : entier non signé hors bornes", f.name)
		}
		fv.SetUint(n)
		return nil
	default:
		return fmt.Errorf("champ %q : type %s attendu", f.name, f.typeName)
	}
}

// maxQuotedKey borne la longueur d'une clé inconnue citée dans un message d'erreur.
const maxQuotedKey = 64

func truncateKey(k string) string {
	if len(k) <= maxQuotedKey {
		return k
	}
	for i := maxQuotedKey; i > 0; i-- {
		if utf8.RuneStart(k[i]) {
			return k[:i] + "…"
		}
	}
	return ""
}

type fieldKind uint8

const (
	kindString fieldKind = iota + 1
	kindBool
	kindInt
	kindUint
	kindBase64
	kindText
)

type fieldInfo struct {
	name     string
	index    []int
	kind     fieldKind
	typeName string
}

var (
	base64Type = reflect.TypeOf(Base64(nil))
	textType   = reflect.TypeOf(Text(nil))
)

var fieldsCache sync.Map // reflect.Type -> map[string]*fieldInfo

// structFields renvoie, par nom JSON, les champs exportés de *T (champs anonymes aplatis).
func structFields(t reflect.Type) map[string]*fieldInfo {
	if cached, ok := fieldsCache.Load(t); ok {
		return cached.(map[string]*fieldInfo)
	}
	fields := make(map[string]*fieldInfo)
	elem := t
	for elem.Kind() == reflect.Pointer {
		elem = elem.Elem()
	}
	collectFields(elem, nil, fields)
	fieldsCache.Store(t, fields) // même clé que la recherche : le type tel que reçu
	return fields
}

func collectFields(t reflect.Type, prefix []int, fields map[string]*fieldInfo) {
	if t.Kind() != reflect.Struct {
		return
	}
	for i := range t.NumField() {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "-" {
			continue
		}
		index := append(append([]int(nil), prefix...), i)
		if f.Anonymous && tag == "" {
			collectFields(f.Type, index, fields)
			continue
		}
		if !f.IsExported() {
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		info := &fieldInfo{name: tag, index: index, typeName: f.Type.String()}
		switch {
		case f.Type == base64Type:
			info.kind = kindBase64
		case f.Type == textType:
			info.kind = kindText
		default:
			switch f.Type.Kind() {
			case reflect.String:
				info.kind = kindString
			case reflect.Bool:
				info.kind = kindBool
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				info.kind = kindInt
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				info.kind = kindUint
			default:
				panic("secmem.DecodeStrict : type de champ non supporté " + f.Type.String() + " pour " + tag)
			}
		}
		fields[tag] = info
	}
}
