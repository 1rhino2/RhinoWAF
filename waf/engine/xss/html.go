package xss

// A tiny HTML tokenizer, lenient the way browsers are: it recovers tag
// names, attribute names and attribute values across the sloppy input an
// attacker sends ("<img/src=x onerror=...>", "<a href = javascript:...>").
// It is not a conformant parser, it only needs to find the tokens the
// detector reasons about.

type kind uint8

const (
	kText kind = iota
	kTagOpen
	kTagClose
	kComment
)

type attr struct {
	name  string
	value string
}

type tag struct {
	kind  kind
	name  string
	attrs []attr
}

func lower(s []byte) string {
	b := make([]byte, len(s))
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// stripName drops nulls and control bytes browsers ignore inside a name,
// so "on\x00error" reads "onerror".
func stripName(s []byte) string {
	b := make([]byte, 0, len(s))
	for _, c := range s {
		if c == 0 || c == '\t' || c == '\n' || c == '\r' || c == '\f' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '/' || c == 0
}

// tags walks the input and calls fn for each start or self tag. Comments
// and text are skipped, close tags reported without attrs. Bounded by the
// input length, one pass.
func tags(in []byte, fn func(tag) bool) {
	i := 0
	n := len(in)
	for i < n {
		lt := indexByte(in, '<', i)
		if lt < 0 {
			return
		}
		i = lt + 1
		if i >= n {
			return
		}
		// comment / cdata / doctype
		if in[i] == '!' {
			i = skipBang(in, i)
			continue
		}
		if in[i] == '?' {
			for i < n && in[i] != '>' {
				i++
			}
			continue
		}
		closing := false
		if in[i] == '/' {
			closing = true
			i++
		}
		if i >= n || !isNameStart(in[i]) {
			continue
		}
		ns := i
		for i < n && isNameByte(in[i]) {
			i++
		}
		t := tag{kind: kTagOpen, name: lower(in[ns:i])}
		if closing {
			t.kind = kTagClose
		}
		i = parseAttrs(in, i, &t)
		if !fn(t) {
			return
		}
	}
}

func skipBang(in []byte, i int) int {
	n := len(in)
	if i+2 < n && in[i+1] == '-' && in[i+2] == '-' {
		// <!--> and <!---> close immediately (html5 "abrupt closing")
		if i+3 < n && in[i+3] == '>' {
			return i + 4
		}
		if i+4 < n && in[i+3] == '-' && in[i+4] == '>' {
			return i + 5
		}
		j := i + 3
		for j+2 < n && (in[j] != '-' || in[j+1] != '-' || in[j+2] != '>') {
			j++
		}
		return j + 3
	}
	for i < n && in[i] != '>' {
		i++
	}
	return i + 1
}

func parseAttrs(in []byte, i int, t *tag) int {
	n := len(in)
	for i < n {
		for i < n && isSpace(in[i]) {
			i++
		}
		if i >= n || in[i] == '>' {
			return i + 1
		}
		if in[i] == '<' {
			return i
		}
		// attribute name. a null or control byte inside the name does not end
		// it, browsers just drop those bytes ("on\x00error" is "onerror"),
		// stripName removes them after.
		ns := i
		for i < n && !isNameEnd(in[i]) {
			i++
		}
		name := stripName(in[ns:i])
		for i < n && isSpaceNoSlash(in[i]) {
			i++
		}
		var val string
		if i < n && in[i] == '=' {
			i++
			for i < n && isSpaceNoSlash(in[i]) {
				i++
			}
			val, i = parseValue(in, i)
		}
		if name != "" {
			t.attrs = append(t.attrs, attr{name: name, value: val})
		}
	}
	return i
}

func parseValue(in []byte, i int) (string, int) {
	n := len(in)
	if i >= n {
		return "", i
	}
	q := in[i]
	// backtick quoting is an old ie-ism attackers still use
	if q == '"' || q == '\'' || q == '`' {
		i++
		vs := i
		for i < n && in[i] != q {
			i++
		}
		v := string(in[vs:i])
		if i < n {
			i++
		}
		return v, i
	}
	vs := i
	for i < n && !isSpace(in[i]) && in[i] != '>' {
		i++
	}
	return string(in[vs:i]), i
}

func isSpaceNoSlash(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == 0
}

// isNameEnd terminates an attribute name: real whitespace, =, >, <, /.
// control bytes are not here on purpose, they get stripped, not split on.
func isNameEnd(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
		c == '=' || c == '>' || c == '<' || c == '/'
}

func isNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isNameByte(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9') || c == '-' || c == ':' || c == '_'
}

func indexByte(b []byte, c byte, from int) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
