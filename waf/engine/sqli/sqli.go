// Package sqli detects SQL injection by tokenizing the value the way a
// database parser would and looking at the shape that comes out, instead
// of grepping for "union select". A search for "grant writing tips" is
// three barewords and stays a search. "' or 1=1--" is a closed string, a
// logic operator, a comparison and a comment, which no search box ever
// produces.
//
// The design owes a lot to libinjection: tokenize, fold, fingerprint. The
// classifier is a small set of structural rules rather than a giant
// fingerprint list, so every hit has a reason a human can read.
package sqli

import (
	"bytes"
	"sync"
)

// Result explains a hit.
type Result struct {
	Fingerprint string
	Ctx         Context
	Reason      string
	Start, End  int // byte span of the decisive token(s) in the input
}

// punctuation that makes sql sql. no quote, paren, comment or comparison
// means the only possible hit is a bare "union select".
const sqlPunct = "'\"`();=<>-#/|&!*,\\@:$"

var unionBytes = []byte("union")

var pool = sync.Pool{New: func() any {
	b := make([]Token, 0, maxTokens)
	return &b
}}

// Detect returns true when in looks like injected sql in any context.
func Detect(in []byte) (Result, bool) {
	if len(in) == 0 {
		return Result{}, false
	}
	if len(in) > 4096 {
		in = in[:4096]
	}
	if !bytes.ContainsAny(in, sqlPunct) && !containsFold(in, unionBytes) {
		return Result{}, false
	}
	bufp := pool.Get().(*[]Token)
	foldp := pool.Get().(*[]Token)
	defer pool.Put(bufp)
	defer pool.Put(foldp)

	ctxs := [3]Context{CtxNone, 255, 255}
	if bytes.IndexByte(in, '\'') >= 0 {
		ctxs[1] = CtxSingle
	}
	if bytes.IndexByte(in, '"') >= 0 {
		ctxs[2] = CtxDouble
	}
	for _, ctx := range ctxs {
		if ctx == 255 {
			continue
		}
		toks := Tokenize(in, ctx, *bufp)
		folded := Fold(toks, *foldp)
		if r, ok := classify(folded, ctx); ok {
			r.Ctx = ctx
			r.Fingerprint = Fingerprint(folded)
			return r, true
		}
	}
	return Result{}, false
}

func containsFold(hay, needle []byte) bool {
	if len(needle) == 0 || len(hay) < len(needle) {
		return false
	}
outer:
	for i := 0; i+len(needle) <= len(hay); i++ {
		for j := range needle {
			c := hay[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

func span(toks []Token, i, j int) (int, int) {
	if i < 0 {
		i = 0
	}
	if j >= len(toks) {
		j = len(toks) - 1
	}
	return toks[i].Pos, toks[j].Pos + len(toks[j].Val)
}

// isCmp is a comparison operator, the thing a tautology needs
func isCmp(tk Token) bool {
	if tk.Type != TOp {
		return false
	}
	switch string(tk.Val) {
	case "=", "<", ">", "<=", ">=", "<>", "!=", "<=>", "like", "rlike", "regexp", "ilike", "in", "is", "between", "not like", "not in", "is not", "not between", "not regexp",
		"LIKE", "IN", "IS", "BETWEEN", "Like", "In", "Is":
		return true
	}
	// word operators arrive in any case
	return len(tk.Val) > 1 && isWordStart(tk.Val[0])
}

// classify is the whole ruleset. Order matters only for which reason wins.
func classify(t []Token, ctx Context) (Result, bool) {
	n := len(t)
	if n == 0 {
		return Result{}, false
	}

	// rule: evil function call anywhere. sleep(5), benchmark(...), xp_cmdshell(...)
	for i, tk := range t {
		if tk.Type == TEvilFunc {
			s, e := span(t, i, i)
			return Result{Reason: "dangerous sql function " + string(tk.Val), Start: s, End: e}, true
		}
	}

	// rule: union followed by select (optionally through parens)
	for i, tk := range t {
		if tk.Type != TUnion {
			continue
		}
		for j := i + 1; j < n && j <= i+3; j++ {
			if t[j].Type == TLParen {
				continue
			}
			if t[j].Type == TEvil {
				s, e := span(t, i, j)
				return Result{Reason: "union select", Start: s, End: e}, true
			}
			break
		}
	}

	// rule: stacked query. ; then a statement, or a string closed then ; then statement
	for i := 0; i+1 < n; i++ {
		if t[i].Type == TSemi && (t[i+1].Type == TEvil || t[i+1].Type == TEvilFunc) {
			s, e := span(t, i, i+1)
			return Result{Reason: "stacked query", Start: s, End: e}, true
		}
	}

	quoted := ctx != CtxNone
	hasComment := false
	for _, tk := range t {
		if tk.Type == TComment {
			hasComment = true
		}
	}

	// rule: tautology. a logic operator followed by "operand cmp operand".
	// bareword operands ("cats and dogs = love") only count inside a quote
	// context or with a comment, numbers and strings always count.
	for i := 0; i < n; i++ {
		if t[i].Type != TLogic {
			continue
		}
		j := i + 1
		for j < n && t[j].Type == TLParen {
			j++
		}
		if j+2 < n && isOperand(t[j].Type) && isCmp(t[j+1]) && (isOperand(t[j+2].Type) || t[j+2].Type == TLParen || t[j+2].Type == TEvil) {
			strong := t[j].Type != TBare || t[j+2].Type != TBare
			if strong || quoted || hasComment {
				s, e := span(t, i, j+2)
				return Result{Reason: "boolean tautology", Start: s, End: e}, true
			}
		}
		// "or true", "or 1" then comment or end-of-input in a quote context
		if j < n && (t[j].Type == TNumber || t[j].Type == TString || t[j].Type == TVar) {
			if (j+1 < n && t[j+1].Type == TComment) || (quoted && j+1 == n) {
				s, e := span(t, i, j)
				return Result{Reason: "logic operator before comment", Start: s, End: e}, true
			}
			// quoted + "or 1" then ) or ; is also enough: "') or 1" ...
			if quoted && j+1 < n && (t[j+1].Type == TRParen || t[j+1].Type == TSemi) {
				s, e := span(t, i, j)
				return Result{Reason: "logic operator after closed string", Start: s, End: e}, true
			}
		}
		// "or sleep(" already caught; "or (select" / "and exists(select"
		if j < n && (t[j].Type == TEvil || t[j].Type == TUnion) {
			s, e := span(t, i, j)
			return Result{Reason: "logic operator before statement", Start: s, End: e}, true
		}
	}

	if quoted {
		// input starts with the closing of the server's string
		first := t[0]
		if first.Type == TString && n >= 2 {
			// s c  -> admin'-- , admin'#, admin'/*
			if t[1].Type == TComment && (t[1].Open != '#' || !t[1].SpaceBefore) {
				s, e := span(t, 0, 1)
				return Result{Reason: "string closed then comment", Start: s, End: e}, true
			}
			// s o s -> '='  , 'a'='a
			if n >= 3 && isCmp(t[1]) && (t[2].Type == TString || t[2].Type == TNumber) {
				s, e := span(t, 0, 2)
				return Result{Reason: "comparison after closed string", Start: s, End: e}, true
			}
			// s then a sql clause then a comment: admin' order by 5--,
			// ' having 1=1--, ' into outfile '..'-- . the clause words are
			// the "strong" ones that don't show up after a quote in prose.
			if t[1].Type == TKeyword || t[1].Type == TEvil {
				if isStrong(t[1].Val) {
					s, e := span(t, 0, 1)
					return Result{Reason: "clause after closed string", Start: s, End: e}, true
				}
			}

			// s U / s ; E / s ) ... & handled above
			if t[1].Type == TUnion || (t[1].Type == TSemi && n >= 3 && t[2].Type == TEvil) {
				s, e := span(t, 0, 1)
				return Result{Reason: "statement after closed string", Start: s, End: e}, true
			}
			// s ) c  and  s ) ) c : closing parens then comment
			if t[1].Type == TRParen {
				k := 1
				for k < n && t[k].Type == TRParen {
					k++
				}
				if k < n && (t[k].Type == TComment || t[k].Type == TSemi || t[k].Type == TUnion) {
					s, e := span(t, 0, k)
					return Result{Reason: "closed string and paren then comment", Start: s, End: e}, true
				}
				if k < n && t[k].Type == TLogic {
					s, e := span(t, 0, k)
					return Result{Reason: "closed string and paren then logic", Start: s, End: e}, true
				}
			}
			// s & ... with anything after (and comment or end), e.g. ' or true, ' and 'x
			if t[1].Type == TLogic && n >= 3 && (t[2].Type == TString || t[2].Type == TNumber || t[2].Type == TVar || t[2].Type == TFunc) {
				if n == 3 || t[3].Type == TComment || isCmp(t[3]) || t[3].Type == TRParen {
					s, e := span(t, 0, 2)
					return Result{Reason: "logic after closed string", Start: s, End: e}, true
				}
			}
		}
	}

	return Result{}, false
}
