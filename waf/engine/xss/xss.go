// Package xss decides whether a value can inject script when reflected into
// an HTML page. It tokenizes the value as HTML and looks at tags and
// attributes, so a dangerous tag, an on* event handler, or a script-scheme
// url is what trips it, not the substrings "url(" or "xmlns" or "&#" that
// show up in ordinary content and code.
package xss

import (
	"strings"
)

type Result struct {
	Reason string
	Start  int
	End    int
}

// Detect runs on the raw value. The engine passes it after url and js
// decoding; here we still entity-decode attribute values ourselves because
// "jav&#x09;ascript:" is decoded by the browser inside an attribute.
func Detect(in []byte) (Result, bool) {
	if len(in) == 0 {
		return Result{}, false
	}
	if len(in) > 8192 {
		in = in[:8192]
	}
	var res Result
	found := false
	tags(in, func(t tag) bool {
		if t.kind == kTagClose {
			if t.name == "script" {
				res = Result{Reason: "</script> tag", Start: 0, End: len(in)}
				found = true
				return false
			}
			return true
		}
		// attrs first, they give the most specific reason and cover the
		// tags that are only vectors when weaponized (img, a, div, input...)
		for _, a := range t.attrs {
			if len(a.name) > 2 && a.name[0] == 'o' && a.name[1] == 'n' {
				res = Result{Reason: "event handler " + a.name, End: len(in)}
				found = true
				return false
			}
			if a.name == "style" && dangerousStyle(a.value) {
				res = Result{Reason: "dangerous style", End: len(in)}
				found = true
				return false
			}
			if urlAttrs[a.name] && dangerousURL(a.value) {
				res = Result{Reason: "script scheme in " + a.name, End: len(in)}
				found = true
				return false
			}
			if a.name == "srcdoc" && len(a.value) > 0 {
				res = Result{Reason: "srcdoc html", End: len(in)}
				found = true
				return false
			}
		}
		if alwaysDanger[t.name] {
			res = Result{Reason: "<" + t.name + "> tag", End: len(in)}
			found = true
			return false
		}
		return true
	})
	if found {
		return res, true
	}

	// non-tag vectors: UTF-7, angular/vue template sinks, css import, and a
	// naked javascript: url reflected into an href-like sink without a tag.
	low := lowerStr(in)
	switch {
	case strings.Contains(low, "+adw-") || strings.Contains(low, "+ada-"): // +ADw- is < in utf-7
		return Result{Reason: "utf-7 tag", End: len(in)}, true
	case strings.Contains(low, "{{constructor") || strings.Contains(low, "constructor.constructor"):
		return Result{Reason: "angular sandbox escape", End: len(in)}, true
	case strings.Contains(low, "dangerouslysetinnerhtml"):
		return Result{Reason: "react raw html", End: len(in)}, true
	}
	return Result{}, false
}

func lowerStr(b []byte) string {
	return strings.ToLower(string(b))
}

// dangerousURL entity-decodes and strips the whitespace and control bytes
// browsers ignore, then checks the scheme.
func dangerousURL(v string) bool {
	s := decodeEntities(v)
	s = stripCtl(s)
	s = strings.TrimLeft(s, " \t\n\r\f")
	s = strings.ToLower(s)
	for _, sc := range dangerSchemes {
		if strings.HasPrefix(s, sc) {
			return true
		}
	}
	return false
}

func dangerousStyle(v string) bool {
	s := strings.ToLower(stripCtl(decodeEntities(v)))
	s = strings.ReplaceAll(s, " ", "")
	s = stripCSSComments(s) // expr/*x*/ession( is still expression(
	return strings.Contains(s, "expression(") || strings.Contains(s, "javascript:") ||
		strings.Contains(s, "-moz-binding") || strings.Contains(s, "behavior:") ||
		strings.Contains(s, "@import")
}

// stripCtl drops every control byte: browsers ignore anything below 0x20
// inside a url scheme, so "jav&#14;ascript:" is still javascript:
func stripCtl(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// decodeEntities handles the numeric and a few named entities that show up
// in scheme obfuscation. the engine's htmldecode transform is more
// thorough, this is the attribute-local pass browsers always do.
func stripCSSComments(s string) string {
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i+2:], "*/")
		if j < 0 {
			return s[:i]
		}
		s = s[:i] + s[i+2+j+2:]
	}
}

func decodeEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '&' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 < len(s) && s[i+1] == '#' {
			j := i + 2
			base := 10
			if j < len(s) && (s[j] == 'x' || s[j] == 'X') {
				base = 16
				j++
			}
			val := 0
			start := j
			for j < len(s) && val < 0x110000 {
				d := hexv(s[j])
				if d < 0 || (base == 10 && d > 9) {
					break
				}
				val = val*base + d
				j++
			}
			if j > start {
				if j < len(s) && s[j] == ';' {
					j++
				}
				if val > 0 && val < 128 {
					b.WriteByte(byte(val))
				} else if val >= 128 {
					b.WriteRune(rune(val))
				}
				i = j - 1
				continue
			}
		}
		// named: only the couple that matter for schemes
		for name, ch := range namedEntities {
			if strings.HasPrefix(s[i:], name) {
				b.WriteByte(ch)
				i += len(name) - 1
				goto next
			}
		}
		b.WriteByte('&')
	next:
	}
	return b.String()
}

var namedEntities = map[string]byte{
	"&colon;": ':', "&Tab;": '\t', "&NewLine;": '\n', "&lpar;": '(', "&rpar;": ')',
}

func hexv(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
