// Package transform holds the decoders and normalizers a rule can chain in
// front of its operator. Each one is a single forward pass over the input
// and never calls another transform, so a chain is exactly what the rule
// says it is: "urldecode, lower" decodes once. Double decoding is a separate
// rule with "urldecode, urldecode", not a hidden fixed-point loop, which is
// how "%u" and "&#" stopped being blanket blocks and started being decoded
// and inspected like everything else.
package transform

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
	"unicode/utf8"
)

type ID uint8

const (
	None ID = iota
	Lowercase
	URLDecode     // %XX and + to space, single pass, bad %ZZ left as is
	URLDecodeUni  // URLDecode plus IIS %uXXXX and fullwidth ASCII folding
	HTMLDecode    // &lt; &#60; &#x3c; also leading zeros, missing semicolon
	JSDecode      // \xHH \uHHHH \u{H..} \OOO and the usual \n \t escapes
	CSSDecode     // \HH..HHHHHH with optional trailing space
	UTF8Normalize // invalid and overlong sequences become U+FFFD
	RemoveNulls
	CompressWS // runs of whitespace to one space
	RemoveWS
	RemoveComments     // sql: /* */ to a space, -- and # to end of line
	RemoveCommentsChar // strips the chars themselves: /* */ -- #
	Base64Decode       // only when the whole value is base64 shaped
	HexDecode          // only when even length and all hex
	NormalizePath      // dot segments and // collapse, keeps the leading /
	NormalizePathWin   // same plus backslash to slash
	Trim
	CmdLine // crs cmdLine: drop \ ^ ' " , ; lower, squeeze ws around / and (
	maxID
)

var names = map[string]ID{
	"lower": Lowercase, "lowercase": Lowercase,
	"urldecode": URLDecode, "urldecode_uni": URLDecodeUni, "urldecodeuni": URLDecodeUni,
	"htmldecode": HTMLDecode, "jsdecode": JSDecode, "cssdecode": CSSDecode,
	"utf8": UTF8Normalize, "utf8normalize": UTF8Normalize,
	"nulls": RemoveNulls, "remove_nulls": RemoveNulls,
	"compress_ws": CompressWS, "compresswhitespace": CompressWS,
	"remove_ws": RemoveWS, "removewhitespace": RemoveWS,
	"remove_comments": RemoveComments, "removecomments": RemoveComments,
	"remove_comments_char": RemoveCommentsChar, "removecommentschar": RemoveCommentsChar,
	"base64decode": Base64Decode, "base64": Base64Decode,
	"hexdecode":      HexDecode,
	"normalize_path": NormalizePath, "normalizepath": NormalizePath,
	"normalize_path_win": NormalizePathWin, "normalizepathwin": NormalizePathWin,
	"trim":    Trim,
	"cmdline": CmdLine,
}

var nameOf = func() map[ID]string {
	m := map[ID]string{}
	for n, id := range names {
		// keep the snake_case spelling as canonical
		if cur, ok := m[id]; !ok || strings.Contains(n, "_") || len(n) < len(cur) {
			m[id] = n
		}
	}
	return m
}()

func (id ID) String() string { return nameOf[id] }

func Parse(name string) (ID, error) {
	id, ok := names[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return None, fmt.Errorf("unknown transform %q", name)
	}
	return id, nil
}

func ParseChain(list []string) ([]ID, error) {
	out := make([]ID, 0, len(list))
	for _, n := range list {
		if n == "" {
			continue
		}
		id, err := Parse(n)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// Apply writes the transformed src into dst[:0] and returns it. dst may be
// nil. The returned slice never aliases src, so callers can ping-pong two
// buffers through a chain without copying.
func Apply(id ID, dst, src []byte) []byte {
	dst = dst[:0]
	switch id {
	case None:
		return append(dst, src...)
	case Lowercase:
		return lower(dst, src)
	case URLDecode:
		return urlDecode(dst, src, false)
	case URLDecodeUni:
		return urlDecode(dst, src, true)
	case HTMLDecode:
		return htmlDecode(dst, src)
	case JSDecode:
		return jsDecode(dst, src)
	case CSSDecode:
		return cssDecode(dst, src)
	case UTF8Normalize:
		return utf8Normalize(dst, src)
	case RemoveNulls:
		for _, c := range src {
			if c != 0 {
				dst = append(dst, c)
			}
		}
		return dst
	case CompressWS:
		return compressWS(dst, src)
	case RemoveWS:
		for _, c := range src {
			if !isWS(c) {
				dst = append(dst, c)
			}
		}
		return dst
	case RemoveComments:
		return removeComments(dst, src, false)
	case RemoveCommentsChar:
		return removeComments(dst, src, true)
	case Base64Decode:
		return base64Decode(dst, src)
	case HexDecode:
		return hexDecode(dst, src)
	case NormalizePath:
		return normalizePath(dst, src, false)
	case NormalizePathWin:
		return normalizePath(dst, src, true)
	case Trim:
		return append(dst, trimBytes(src)...)
	case CmdLine:
		return cmdLine(dst, src)
	}
	return append(dst, src...)
}

// Run applies a whole chain using two scratch buffers. The result lives in
// one of the scratch buffers, copy it if you need to keep it.
func Run(chain []ID, src []byte, a, b []byte) (out, sparea, spareb []byte) {
	if len(chain) == 0 {
		return src, a, b
	}
	cur := src
	for _, id := range chain {
		a = Apply(id, a, cur)
		cur = a
		a, b = b, a
	}
	return cur, a, b
}

func isWS(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func lower(dst, src []byte) []byte {
	for _, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func urlDecode(dst, src []byte, uni bool) []byte {
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '+':
			dst = append(dst, ' ')
		case c == '%' && uni && i+5 < len(src) && (src[i+1] == 'u' || src[i+1] == 'U'):
			// iis %uXXXX. fullwidth forms (U+FF01..FF5E) fold to ascii, that is
			// the classic %uFF1C bypass for <
			var r rune
			ok := true
			for j := 2; j < 6; j++ {
				h, hok := unhex(src[i+j])
				if !hok {
					ok = false
					break
				}
				r = r<<4 | rune(h)
			}
			if !ok {
				dst = append(dst, c)
				continue
			}
			if r >= 0xFF01 && r <= 0xFF5E {
				r = r - 0xFF01 + 0x21
			}
			dst = utf8.AppendRune(dst, r)
			i += 5
		case c == '%' && i+2 < len(src):
			hi, ok1 := unhex(src[i+1])
			lo, ok2 := unhex(src[i+2])
			if ok1 && ok2 {
				dst = append(dst, hi<<4|lo)
				i += 2
			} else {
				dst = append(dst, c)
			}
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

// htmlDecode: stdlib handles the named entities and the numeric forms, but
// it wants a semicolon for some and it does not fold &#0000060; style
// zero padding beyond what browsers do. Pre-pass numerics ourselves, hand
// the rest to html.UnescapeString.
func htmlDecode(dst, src []byte) []byte {
	if indexByte(src, '&') < 0 {
		return append(dst, src...)
	}
	tmp := make([]byte, 0, len(src))
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c != '&' || i+2 >= len(src) || src[i+1] != '#' {
			tmp = append(tmp, c)
			continue
		}
		j := i + 2
		base := 10
		if j < len(src) && (src[j] == 'x' || src[j] == 'X') {
			base = 16
			j++
		}
		var r rune
		digits := 0
		over := false
		for j < len(src) {
			d, ok := unhex(src[j])
			if !ok || (base == 10 && d > 9) {
				break
			}
			if !over {
				r = r*rune(base) + rune(d)
				if r > utf8.MaxRune {
					over = true
				}
			}
			j++
			digits++
		}
		if digits == 0 {
			tmp = append(tmp, c)
			continue
		}
		if j < len(src) && src[j] == ';' {
			j++
		}
		if over || r == 0 || r > utf8.MaxRune {
			r = utf8.RuneError
		}
		tmp = utf8.AppendRune(tmp, r)
		i = j - 1
	}
	if indexByte(tmp, '&') < 0 {
		return append(dst, tmp...)
	}
	return append(dst, html.UnescapeString(string(tmp))...)
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func jsDecode(dst, src []byte) []byte {
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c != '\\' || i+1 >= len(src) {
			dst = append(dst, c)
			continue
		}
		n := src[i+1]
		switch n {
		case 'x', 'X':
			if i+3 < len(src) {
				hi, ok1 := unhex(src[i+2])
				lo, ok2 := unhex(src[i+3])
				if ok1 && ok2 {
					dst = append(dst, hi<<4|lo)
					i += 3
					continue
				}
			}
			dst = append(dst, c)
		case 'u':
			// \u{1F600} or \uXXXX
			if i+2 < len(src) && src[i+2] == '{' {
				var r rune
				j := i + 3
				digits := 0
				for j < len(src) && src[j] != '}' && digits < 8 {
					h, ok := unhex(src[j])
					if !ok {
						break
					}
					r = r<<4 | rune(h)
					j++
					digits++
				}
				if j < len(src) && src[j] == '}' && digits > 0 && r <= utf8.MaxRune {
					dst = utf8.AppendRune(dst, r)
					i = j
					continue
				}
				dst = append(dst, c)
				continue
			}
			if i+5 < len(src) {
				var r rune
				ok := true
				for j := 2; j < 6; j++ {
					h, hok := unhex(src[i+j])
					if !hok {
						ok = false
						break
					}
					r = r<<4 | rune(h)
				}
				if ok {
					dst = utf8.AppendRune(dst, r)
					i += 5
					continue
				}
			}
			dst = append(dst, c)
		case '0', '1', '2', '3', '4', '5', '6', '7':
			// up to 3 octal digits
			var v int
			j := i + 1
			for k := 0; k < 3 && j < len(src) && src[j] >= '0' && src[j] <= '7'; k++ {
				v = v*8 + int(src[j]-'0')
				j++
			}
			if v > 255 {
				v = 255
			}
			dst = append(dst, byte(v))
			i = j - 1
		case 'n':
			dst = append(dst, '\n')
			i++
		case 't':
			dst = append(dst, '\t')
			i++
		case 'r':
			dst = append(dst, '\r')
			i++
		case 'b':
			dst = append(dst, '\b')
			i++
		case 'f':
			dst = append(dst, '\f')
			i++
		case 'v':
			dst = append(dst, '\v')
			i++
		case '\\', '\'', '"', '/':
			dst = append(dst, n)
			i++
		default:
			// unknown escape: browsers drop the backslash
			dst = append(dst, n)
			i++
		}
	}
	return dst
}

func cssDecode(dst, src []byte) []byte {
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c != '\\' || i+1 >= len(src) {
			dst = append(dst, c)
			continue
		}
		var r rune
		j := i + 1
		digits := 0
		for j < len(src) && digits < 6 {
			h, ok := unhex(src[j])
			if !ok {
				break
			}
			r = r<<4 | rune(h)
			j++
			digits++
		}
		if digits == 0 {
			// \X escapes X itself
			dst = append(dst, src[i+1])
			i++
			continue
		}
		// one optional whitespace terminates the escape
		if j < len(src) && isWS(src[j]) {
			j++
		}
		if r == 0 || r > utf8.MaxRune {
			r = utf8.RuneError
		}
		dst = utf8.AppendRune(dst, r)
		i = j - 1
	}
	return dst
}

// utf8Normalize replaces invalid bytes and overlong encodings with U+FFFD.
// Overlongs matter because %c0%ae is "." to a lenient decoder and that is
// the oldest traversal bypass there is. Output is at most 3x input.
func utf8Normalize(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		c := src[i]
		if c < 0x80 {
			dst = append(dst, c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size <= 1 {
			// DecodeRune already rejects overlongs and surrogates, so anything
			// landing here is junk. we eat one byte and move on.
			dst = append(dst, "�"...)
			i++
			continue
		}
		dst = append(dst, src[i:i+size]...)
		i += size
	}
	return dst
}

func compressWS(dst, src []byte) []byte {
	inWS := false
	for _, c := range src {
		if isWS(c) {
			if !inWS {
				dst = append(dst, ' ')
				inWS = true
			}
			continue
		}
		inWS = false
		dst = append(dst, c)
	}
	return dst
}

// removeComments handles sql style. With char=false a /* */ block becomes
// one space (so "un/**/ion" reads "un ion", which the tokenizer folds) and
// -- or # runs to end of line. char=true only strips the delimiters, which
// is what "uni/**/on" evasions need to become "union".
func removeComments(dst, src []byte, char bool) []byte {
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			end := i + 2
			for end+1 < len(src) && (src[end] != '*' || src[end+1] != '/') {
				end++
			}
			if end+1 < len(src) {
				if !char {
					dst = append(dst, ' ')
				}
				i = end + 1
				continue
			}
			// unterminated: drop the rest, same as a db would
			if !char {
				dst = append(dst, ' ')
				return dst
			}
			i++
			continue
		}
		if char {
			if c == '-' && i+1 < len(src) && src[i+1] == '-' {
				i++
				continue
			}
			if c == '#' {
				continue
			}
			dst = append(dst, c)
			continue
		}
		if (c == '-' && i+1 < len(src) && src[i+1] == '-') || c == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			dst = append(dst, ' ')
			continue
		}
		dst = append(dst, c)
	}
	return dst
}

// Base64Shaped is the gate for Base64Decode and the "opaque" flag. Real
// tokens are long, use only the alphabet and are a multiple of 4 or carry
// padding. A search term is not.
func Base64Shaped(b []byte) bool {
	if len(b) < 16 {
		return false
	}
	pad := 0
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '-', c == '_':
			if pad > 0 {
				return false
			}
		case c == '=':
			pad++
			if pad > 2 || i < len(b)-2 {
				return false
			}
		default:
			return false
		}
	}
	return len(b)%4 == 0 || pad > 0 || len(b) >= 32
}

func base64Decode(dst, src []byte) []byte {
	if !Base64Shaped(src) {
		return append(dst, src...)
	}
	s := strings.TrimRight(string(src), "=")
	enc := base64.RawStdEncoding
	if strings.ContainsAny(s, "-_") {
		enc = base64.RawURLEncoding
	}
	out := make([]byte, enc.DecodedLen(len(s)))
	n, err := enc.Decode(out, []byte(s))
	if err != nil {
		return append(dst, src...)
	}
	return append(dst, out[:n]...)
}

func hexDecode(dst, src []byte) []byte {
	if len(src) == 0 || len(src)%2 != 0 {
		return append(dst, src...)
	}
	for _, c := range src {
		if _, ok := unhex(c); !ok {
			return append(dst, src...)
		}
	}
	out := make([]byte, len(src)/2)
	if _, err := hex.Decode(out, src); err != nil {
		return append(dst, src...)
	}
	return append(dst, out...)
}

// normalizePath resolves . and .. segments and collapses repeated slashes.
// A .. that would climb above root is dropped, the traversal detector looks
// at the raw form for that, this is for matching against file lists.
func normalizePath(dst, src []byte, win bool) []byte {
	if len(src) == 0 {
		return dst
	}
	tmp := make([]byte, 0, len(src))
	for _, c := range src {
		if win && c == '\\' {
			c = '/'
		}
		tmp = append(tmp, c)
	}
	abs := tmp[0] == '/'
	var segs [][]byte
	for _, seg := range splitSlash(tmp) {
		switch {
		case len(seg) == 0 || (len(seg) == 1 && seg[0] == '.'):
			continue
		case len(seg) == 2 && seg[0] == '.' && seg[1] == '.':
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, seg)
		}
	}
	if abs {
		dst = append(dst, '/')
	}
	for i, s := range segs {
		if i > 0 {
			dst = append(dst, '/')
		}
		dst = append(dst, s...)
	}
	if len(src) > 1 && src[len(src)-1] == '/' && len(segs) > 0 {
		dst = append(dst, '/')
	}
	return dst
}

func splitSlash(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '/' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return append(out, b[start:])
}

func trimBytes(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isWS(b[i]) {
		i++
	}
	for j > i && isWS(b[j-1]) {
		j--
	}
	return b[i:j]
}

// cmdLine mirrors the crs transform exactly: attackers pad commands with
// quotes and carets ("c^a^t", "c'a't") that the shell removes, so we
// remove them too, commas and semicolons become spaces, whitespace runs
// collapse, and the space before / and ( goes so "cat /etc" reads
// "cat/etc". The shellcmd rules are written against this shape.
func cmdLine(dst, src []byte) []byte {
	pendingWS := false
	for _, c := range src {
		switch c {
		case '\\', '^', '\'', '"':
			continue
		case ',', ';':
			c = ' '
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if isWS(c) {
			pendingWS = true
			continue
		}
		if pendingWS {
			if c != '/' && c != '(' && len(dst) > 0 {
				dst = append(dst, ' ')
			}
			pendingWS = false
		}
		dst = append(dst, c)
	}
	return dst
}
