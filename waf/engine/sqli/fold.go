package sqli

// Fold squeezes a token list into the shape the classifier reasons about:
// function calls become one token, parens around a single value vanish,
// qualified names collapse, adjacent string literals concatenate, leading
// unary operators go, arithmetic between numbers folds to a number.
// Comparisons are kept on purpose, "1 or 1=1" must not look like "1 or 1".
func Fold(in []Token, out []Token) []Token {
	out = out[:0]
	// pass 1: collapse function calls f(...) and X(...) into the name token
	for i := 0; i < len(in); i++ {
		tk := in[i]
		if (tk.Type == TFunc || tk.Type == TEvilFunc) && i+1 < len(in) && in[i+1].Type == TLParen {
			depth := 0
			j := i + 1
			for ; j < len(in); j++ {
				if in[j].Type == TLParen {
					depth++
				} else if in[j].Type == TRParen {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if j < len(in) {
				out = append(out, tk)
				i = j
				continue
			}
			// unbalanced: keep the name, drop the paren, let the rest through
			out = append(out, tk)
			i++
			continue
		}
		out = append(out, tk)
	}

	// pass 2: local rewrites until nothing changes (bounded by length)
	for changed := true; changed; {
		changed = false
		for i := 0; i < len(out); i++ {
			// leading unary + - ~ !
			if i == 0 && out[i].Type == TOp && len(out[i].Val) == 1 && isUnary(out[i].Val[0]) && len(out) > 1 && isOperand(out[1].Type) {
				out = del(out, i, 1)
				changed = true
				break
			}
			// unary after an operator or logic or paren: "= -1", "or !1"
			if i > 0 && i+1 < len(out) && out[i].Type == TOp && len(out[i].Val) == 1 && isUnary(out[i].Val[0]) &&
				(out[i-1].Type == TOp || out[i-1].Type == TLogic || out[i-1].Type == TLParen || out[i-1].Type == TComma) && isOperand(out[i+1].Type) {
				out = del(out, i, 1)
				changed = true
				break
			}
			// ( x ) -> x
			if i+2 < len(out) && out[i].Type == TLParen && isOperand(out[i+1].Type) && out[i+2].Type == TRParen {
				out[i] = out[i+1]
				out = del(out, i+1, 2)
				changed = true
				break
			}
			// s s -> s
			if i+1 < len(out) && out[i].Type == TString && out[i+1].Type == TString {
				out = del(out, i+1, 1)
				changed = true
				break
			}
			// B . B -> B (table.column, also k.B for information_schema.tables)
			if i+2 < len(out) && out[i+1].Type == TDot && isName(out[i].Type) && isName(out[i+2].Type) {
				out[i].Type = TBare
				out = del(out, i+1, 2)
				changed = true
				break
			}
			// n arith n -> n
			if i+2 < len(out) && out[i].Type == TNumber && out[i+2].Type == TNumber && out[i+1].Type == TOp && isArith(out[i+1].Val) {
				out = del(out, i+1, 2)
				changed = true
				break
			}
			// o o -> o  (=- handled above, this is things like "= =")
			if i+1 < len(out) && out[i].Type == TOp && out[i+1].Type == TOp {
				out = del(out, i+1, 1)
				changed = true
				break
			}
			// & & -> & ("or not", "and not")
			if i+1 < len(out) && out[i].Type == TLogic && out[i+1].Type == TLogic {
				out = del(out, i+1, 1)
				changed = true
				break
			}
			// k k -> k, k B k -> k B: collapse runs of plain keywords
			if i+1 < len(out) && out[i].Type == TKeyword && out[i+1].Type == TKeyword {
				out = del(out, i+1, 1)
				changed = true
				break
			}
			// B B -> B: english words, keeps prose short so prose shapes stay recognisable
			if i+1 < len(out) && out[i].Type == TBare && out[i+1].Type == TBare {
				out = del(out, i+1, 1)
				changed = true
				break
			}
			// t and o around cast: "cast(x as int)" already folded, "x::int" -> x
			if i+1 < len(out) && out[i].Type == TOp && string(out[i].Val) == "::" && out[i+1].Type == TType {
				out = del(out, i, 2)
				changed = true
				break
			}
		}
	}
	return out
}

func del(s []Token, i, n int) []Token {
	copy(s[i:], s[i+n:])
	return s[:len(s)-n]
}

func isUnary(c byte) bool { return c == '-' || c == '+' || c == '~' || c == '!' }

func isArith(v []byte) bool {
	if len(v) != 1 {
		return false
	}
	switch v[0] {
	case '+', '-', '*', '/', '%', '^', '|', '&':
		return true
	}
	return false
}

func isOperand(t byte) bool {
	return t == TNumber || t == TString || t == TVar || t == TBare || t == TFunc || t == TEvilFunc
}

func isName(t byte) bool {
	return t == TBare || t == TKeyword || t == TVar || t == TFunc || t == TType
}

// Fingerprint is the first few token types as a string, the thing an
// operator sees in the block evidence.
func Fingerprint(toks []Token) string {
	n := len(toks)
	if n > 8 {
		n = 8
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = toks[i].Type
	}
	return string(b)
}
