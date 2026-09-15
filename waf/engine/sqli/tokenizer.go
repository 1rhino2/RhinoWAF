package sqli

// Context says what the input is assumed to sit inside on the server: a
// bare value, or the inside of a single or double quoted string. The
// tokenizer for CtxSingle pretends an open quote precedes the input, so
// "' or 1=1" reads as an empty string, then or, then 1=1.
type Context byte

const (
	CtxNone Context = iota
	CtxSingle
	CtxDouble
)

func (c Context) String() string {
	switch c {
	case CtxSingle:
		return "single-quote"
	case CtxDouble:
		return "double-quote"
	}
	return "none"
}

type Token struct {
	Type byte
	Val  []byte // slice of the input, or of a small static for merged pairs
	Pos  int
	// for comments: the opener, so the classifier can tell -- from #
	Open byte
	// true when the string was never closed
	Unterminated bool
	// true when there was whitespace before this token
	SpaceBefore bool
}

// maxTokens keeps a pathological input from costing more than a few
// microseconds. Nothing structural needs more than the first few dozen.
const maxTokens = 96

// Tokenize turns in into a token list. Never panics, never allocates the
// input, bounded by maxTokens.
func Tokenize(in []byte, ctx Context, out []Token) []Token {
	t := tokenizer{in: in, out: out[:0]}
	switch ctx {
	case CtxSingle:
		t.openString('\'', 0)
	case CtxDouble:
		t.openString('"', 0)
	}
	for t.pos < len(t.in) && len(t.out) < maxTokens {
		t.step()
	}
	return t.mergePairs()
}

type tokenizer struct {
	in         []byte
	pos        int
	out        []Token
	space      bool
	inlineExec bool // inside /*!...*/ where the body is live sql
}

func (t *tokenizer) emit(typ byte, start, end int) {
	t.out = append(t.out, Token{Type: typ, Val: t.in[start:end], Pos: start, SpaceBefore: t.space})
	t.space = false
}

// openString scans a string body that started at pos (the opening quote is
// at pos-1 or is implied by the context when pos==0 and the quote is not in
// the input).
func (t *tokenizer) openString(q byte, pos int) {
	start := pos
	i := pos
	for i < len(t.in) {
		c := t.in[i]
		if c == '\\' && i+1 < len(t.in) {
			i += 2
			continue
		}
		if c == q {
			if i+1 < len(t.in) && t.in[i+1] == q {
				i += 2 // '' escape
				continue
			}
			t.out = append(t.out, Token{Type: TString, Val: t.in[start:i], Pos: start, SpaceBefore: t.space})
			t.space = false
			t.pos = i + 1
			return
		}
		i++
	}
	t.out = append(t.out, Token{Type: TString, Val: t.in[start:], Pos: start, Unterminated: true, SpaceBefore: t.space})
	t.space = false
	t.pos = len(t.in)
}

func isWordStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isWordByte(c byte) bool {
	return isWordStart(c) || (c >= '0' && c <= '9') || c == '$'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexByte(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == 0xa0
}

func (t *tokenizer) step() {
	c := t.in[t.pos]
	switch {
	case isSpace(c) || c == 0:
		t.space = true
		t.pos++
	case c == '\'' || c == '"' || c == '`':
		t.pos++
		t.openString(c, t.pos)
	case isDigit(c) || (c == '.' && t.pos+1 < len(t.in) && isDigit(t.in[t.pos+1])):
		t.number()
	case c == '$' && t.pos+1 < len(t.in) && t.in[t.pos+1] == '$':
		t.dollarString()
	case isWordStart(c):
		t.word()
	case c == '@' || c == ':' && t.pos+1 < len(t.in) && isWordStart(t.in[t.pos+1]):
		t.variable()
	case c == '$' && t.pos+1 < len(t.in) && isWordStart(t.in[t.pos+1]):
		t.variable()
	case c == '-' && t.pos+1 < len(t.in) && t.in[t.pos+1] == '-':
		t.lineComment('-')
	case c == '#':
		t.lineComment('#')
	case c == '/' && t.pos+1 < len(t.in) && t.in[t.pos+1] == '*':
		t.blockComment()
	case c == '(' || c == ')' || c == ',' || c == ';' || c == '.':
		t.emit(c, t.pos, t.pos+1)
		t.pos++
	case c == '\\':
		t.emit(TBackslash, t.pos, t.pos+1)
		t.pos++
	case c == '{' || c == '}' || c == '[' || c == ']':
		// odbc escapes and json paths: treat braces as parens, brackets pass through as bareword-ish
		switch c {
		case '{':
			t.emit(TLParen, t.pos, t.pos+1)
		case '}':
			t.emit(TRParen, t.pos, t.pos+1)
		default:
			t.emit(TBare, t.pos, t.pos+1)
		}
		t.pos++
	default:
		t.operator()
	}
}

func (t *tokenizer) number() {
	start := t.pos
	i := t.pos
	if t.in[i] == '0' && i+1 < len(t.in) && (t.in[i+1] == 'x' || t.in[i+1] == 'X') {
		i += 2
		for i < len(t.in) && isHexByte(t.in[i]) {
			i++
		}
		t.emit(TNumber, start, i)
		t.pos = i
		return
	}
	for i < len(t.in) && isDigit(t.in[i]) {
		i++
	}
	if i < len(t.in) && t.in[i] == '.' {
		i++
		for i < len(t.in) && isDigit(t.in[i]) {
			i++
		}
	}
	if i < len(t.in) && (t.in[i] == 'e' || t.in[i] == 'E') {
		j := i + 1
		if j < len(t.in) && (t.in[j] == '+' || t.in[j] == '-') {
			j++
		}
		if j < len(t.in) && isDigit(t.in[j]) {
			for j < len(t.in) && isDigit(t.in[j]) {
				j++
			}
			i = j
		}
	}
	// "1abc" is a bareword in mysql land (1union), split it: number then word
	t.emit(TNumber, start, i)
	t.pos = i
}

func (t *tokenizer) dollarString() {
	// $$...$$ or $tag$...$tag$ (postgres)
	start := t.pos
	i := t.pos + 1
	for i < len(t.in) && t.in[i] != '$' {
		i++
	}
	if i >= len(t.in) {
		t.emit(TBare, start, start+1)
		t.pos = start + 1
		return
	}
	tag := t.in[start : i+1]
	j := i + 1
	for j+len(tag) <= len(t.in) {
		if string(t.in[j:j+len(tag)]) == string(tag) {
			t.out = append(t.out, Token{Type: TString, Val: t.in[i+1 : j], Pos: start, SpaceBefore: t.space})
			t.space = false
			t.pos = j + len(tag)
			return
		}
		j++
	}
	t.out = append(t.out, Token{Type: TString, Val: t.in[i+1:], Pos: start, Unterminated: true, SpaceBefore: t.space})
	t.space = false
	t.pos = len(t.in)
}

func (t *tokenizer) word() {
	start := t.pos
	i := t.pos
	for i < len(t.in) && isWordByte(t.in[i]) {
		i++
	}
	w := t.in[start:i]

	// prefixed strings: N'..' x'..' b'..' q'[..]'
	if len(w) == 1 && i < len(t.in) && t.in[i] == '\'' {
		switch w[0] {
		case 'n', 'N', 'x', 'X', 'b', 'B', 'e', 'E', 'q', 'Q', 'u', 'U':
			t.pos = i + 1
			t.openString('\'', t.pos)
			return
		}
	}

	// look past whitespace for a paren: that makes it a function
	j := i
	for j < len(t.in) && isSpace(t.in[j]) {
		j++
	}
	if j < len(t.in) && t.in[j] == '(' {
		if typ, ok := lookupFunc(w); ok {
			t.emit(typ, start, i)
			t.pos = i
			return
		}
	}
	if typ, ok := lookup(w); ok {
		t.emit(typ, start, i)
		t.pos = i
		return
	}
	t.emit(TBare, start, i)
	t.pos = i
}

func (t *tokenizer) variable() {
	start := t.pos
	i := t.pos + 1
	if i < len(t.in) && t.in[i] == '@' {
		i++
	}
	for i < len(t.in) && (isWordByte(t.in[i]) || t.in[i] == '.') {
		i++
	}
	if i == start+1 || (i == start+2 && t.in[start+1] == '@') {
		// lone @ or :: is an operator, not a variable
		t.operator()
		return
	}
	t.emit(TVar, start, i)
	t.pos = i
}

func (t *tokenizer) lineComment(open byte) {
	start := t.pos
	i := t.pos
	for i < len(t.in) && t.in[i] != '\n' {
		i++
	}
	t.out = append(t.out, Token{Type: TComment, Val: t.in[start:i], Pos: start, Open: open, SpaceBefore: t.space})
	t.space = false
	t.pos = i
}

func (t *tokenizer) blockComment() {
	start := t.pos
	// mysql /*! ... */ executes its body, so we tokenize the body instead
	if t.pos+2 < len(t.in) && t.in[t.pos+2] == '!' {
		i := t.pos + 3
		for i < len(t.in) && isDigit(t.in[i]) {
			i++
		}
		t.pos = i
		t.space = true
		t.inlineExec = true
		return
	}
	i := t.pos + 2
	for i+1 < len(t.in) && (t.in[i] != '*' || t.in[i+1] != '/') {
		i++
	}
	end := len(t.in)
	if i+1 < len(t.in) {
		end = i + 2
	}
	t.out = append(t.out, Token{Type: TComment, Val: t.in[start:end], Pos: start, Open: '/', SpaceBefore: t.space})
	t.space = false
	t.pos = end
}

var multiOps = []string{"<=>", "->>", "!<", "!>", "<>", "!=", "<=", ">=", "||", "&&", ":=", "->", "::", "**", "<<", ">>", "|/", "||/"}

func (t *tokenizer) operator() {
	rest := t.in[t.pos:]
	// closing */ of an inline exec comment is whitespace
	if t.inlineExec && len(rest) >= 2 && rest[0] == '*' && rest[1] == '/' {
		t.inlineExec = false
		t.space = true
		t.pos += 2
		return
	}
	for _, op := range multiOps {
		if len(rest) >= len(op) && string(rest[:len(op)]) == op {
			typ := byte(TOp)
			if op == "||" || op == "&&" {
				typ = TLogic
			}
			t.emit(typ, t.pos, t.pos+len(op))
			t.pos += len(op)
			return
		}
	}
	c := rest[0]
	switch c {
	case '=', '<', '>', '+', '-', '*', '/', '%', '^', '~', '!', '|', '&', '?', '@', ':':
		t.emit(TOp, t.pos, t.pos+1)
	default:
		// anything else (unicode punctuation, control) is noise
		t.space = true
	}
	t.pos++
}

// mergePairs collapses "union all", "order by", "insert into" etc into
// one token so the fingerprint stays short and the classifier can ask
// simple questions.
func (t *tokenizer) mergePairs() []Token {
	toks := t.out
	if len(toks) < 2 {
		return toks
	}
	out := toks[:0]
	for i := 0; i < len(toks); i++ {
		cur := toks[i]
		if i+1 < len(toks) {
			nxt := toks[i+1]
			wordish := func(tk Token) bool {
				return tk.Type == TKeyword || tk.Type == TEvil || tk.Type == TUnion || tk.Type == TBare ||
					tk.Type == TOp || tk.Type == TLogic || tk.Type == TType || tk.Type == TNumber || tk.Type == TEvilFunc
			}
			if wordish(cur) && wordish(nxt) && isWordStart(cur.Val[0]) && isWordStart(nxt.Val[0]) {
				if typ, ok := lookupPair(cur.Val, nxt.Val); ok {
					merged := Token{Type: typ, Val: t.in[cur.Pos : nxt.Pos+len(nxt.Val)], Pos: cur.Pos, SpaceBefore: cur.SpaceBefore}
					// three-word forms: left outer join, not like etc handled by a second pass below
					out = append(out, merged)
					i++
					continue
				}
			}
		}
		out = append(out, cur)
	}
	// second pass for "left outer" + "join", "union all" already merged
	toks = out
	out = toks[:0]
	for i := 0; i < len(toks); i++ {
		cur := toks[i]
		if i+1 < len(toks) && cur.Type == TKeyword && toks[i+1].Type == TKeyword {
			if typ, ok := lookupPair(cur.Val, toks[i+1].Val); ok {
				nxt := toks[i+1]
				out = append(out, Token{Type: typ, Val: t.in[cur.Pos : nxt.Pos+len(nxt.Val)], Pos: cur.Pos, SpaceBefore: cur.SpaceBefore})
				i++
				continue
			}
		}
		out = append(out, cur)
	}
	return out
}
