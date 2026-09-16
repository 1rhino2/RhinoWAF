package engine

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"

	"rhinowaf/waf/engine/ac"
	"rhinowaf/waf/engine/pathnorm"
	"rhinowaf/waf/engine/sqli"
	"rhinowaf/waf/engine/xss"
)

// Operator is the test a condition runs against one transformed value.
// Match returns the byte span so the block evidence can show what hit.
type Operator interface {
	Match(v []byte) (start, end int, ok bool)
	Name() string
	// hints are literal substrings that must be present for a match, used by
	// the prefilter. nil means "cannot prefilter, always run me".
	hints() [][]byte
}

// dataLoader resolves @data/foo.txt to its lines.
type dataLoader func(path string) ([][]byte, error)

func buildOperator(name, arg string, load dataLoader) (Operator, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	arg = strings.TrimSpace(arg)
	switch name {
	case "contains":
		return &containsOp{needle: []byte(strings.ToLower(arg))}, nil
	case "containsword":
		return &wordOp{needle: strings.ToLower(arg)}, nil
	case "beginswith":
		return &affixOp{s: []byte(strings.ToLower(arg))}, nil
	case "endswith":
		return &affixOp{s: []byte(strings.ToLower(arg)), end: true}, nil
	case "streq":
		return &streqOp{s: []byte(arg)}, nil
	case "within":
		return &withinOp{set: splitList(arg)}, nil
	case "len":
		return newNumOp("len", arg)
	case "eq", "gt", "lt", "ge", "le":
		return newCmpOp(name, arg)
	case "rx":
		return newRxOp(arg)
	case "pm":
		return newPMOp(arg, load, false)
	case "pmfile", "pmfrom":
		return newPMOp(arg, load, true)
	case "sqli":
		return sqliOp{}, nil
	case "xss":
		return xssOp{}, nil
	case "detectpath":
		return pathOp{}, nil
	case "detectxxe":
		return xxeOp{}, nil
	case "shellcmd":
		return newShellOp(arg, load)
	case "ssrfhost":
		return ssrfOp{}, nil
	case "jndi":
		return jndiOp{}, nil
	case "byterange":
		return newByteRangeOp(arg)
	case "validutf8":
		return validUTF8Op{}, nil
	case "unconditional":
		return uncondOp{}, nil
	}
	return nil, fmt.Errorf("unknown operator %q", name)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- string operators ---

type containsOp struct{ needle []byte }

// Match is case-insensitive without copying v: the needle is already lower
func (o *containsOp) Match(v []byte) (int, int, bool) {
	n := len(o.needle)
	if n == 0 || n > len(v) {
		return 0, 0, false
	}
outer:
	for i := 0; i+n <= len(v); i++ {
		for j := 0; j < n; j++ {
			c := v[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != o.needle[j] {
				continue outer
			}
		}
		return i, i + n, true
	}
	return 0, 0, false
}
func (o *containsOp) Name() string    { return "contains" }
func (o *containsOp) hints() [][]byte { return [][]byte{o.needle} }

type wordOp struct{ needle string }

func (o *wordOp) Match(v []byte) (int, int, bool) {
	s := strings.ToLower(string(v))
	from := 0
	for {
		i := strings.Index(s[from:], o.needle)
		if i < 0 {
			return 0, 0, false
		}
		i += from
		lb := i == 0 || !isWordByte(s[i-1])
		rb := i+len(o.needle) >= len(s) || !isWordByte(s[i+len(o.needle)])
		if lb && rb {
			return i, i + len(o.needle), true
		}
		from = i + 1
	}
}
func (o *wordOp) Name() string    { return "containsword" }
func (o *wordOp) hints() [][]byte { return [][]byte{[]byte(o.needle)} }

func isWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

type affixOp struct {
	s   []byte
	end bool
}

func (o *affixOp) Match(v []byte) (int, int, bool) {
	lv := bytes.ToLower(v)
	if o.end {
		if bytes.HasSuffix(lv, o.s) {
			return len(v) - len(o.s), len(v), true
		}
		return 0, 0, false
	}
	if bytes.HasPrefix(lv, o.s) {
		return 0, len(o.s), true
	}
	return 0, 0, false
}
func (o *affixOp) Name() string    { return "affix" }
func (o *affixOp) hints() [][]byte { return [][]byte{o.s} }

type streqOp struct{ s []byte }

func (o *streqOp) Match(v []byte) (int, int, bool) {
	if bytes.Equal(v, o.s) {
		return 0, len(v), true
	}
	return 0, 0, false
}
func (o *streqOp) Name() string    { return "streq" }
func (o *streqOp) hints() [][]byte { return nil }

type withinOp struct{ set []string }

func (o *withinOp) Match(v []byte) (int, int, bool) {
	s := string(v)
	for _, x := range o.set {
		if strings.EqualFold(s, x) {
			return 0, len(v), true
		}
	}
	return 0, 0, false
}
func (o *withinOp) Name() string    { return "within" }
func (o *withinOp) hints() [][]byte { return nil }

// --- numeric operators ---

type numOp struct {
	kind string // len
	n    int
	cmp  string // >, <, >=, ... default >
}

func newNumOp(kind, arg string) (Operator, error) {
	cmp, num := splitCmp(arg)
	n, err := strconv.Atoi(num)
	if err != nil {
		return nil, fmt.Errorf("%s wants a number, got %q", kind, arg)
	}
	return &numOp{kind: kind, n: n, cmp: cmp}, nil
}

func (o *numOp) Match(v []byte) (int, int, bool) {
	if compareInt(len(v), o.cmp, o.n) {
		return 0, len(v), true
	}
	return 0, 0, false
}
func (o *numOp) Name() string    { return o.kind }
func (o *numOp) hints() [][]byte { return nil }

type cmpOp struct {
	cmp string
	n   float64
}

func newCmpOp(name, arg string) (Operator, error) {
	n, err := strconv.ParseFloat(strings.TrimSpace(arg), 64)
	if err != nil {
		return nil, fmt.Errorf("%s wants a number, got %q", name, arg)
	}
	return &cmpOp{cmp: name, n: n}, nil
}

func (o *cmpOp) Match(v []byte) (int, int, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(string(v)), 64)
	if err != nil {
		return 0, 0, false
	}
	ok := false
	switch o.cmp {
	case "eq":
		ok = f == o.n
	case "gt":
		ok = f > o.n
	case "lt":
		ok = f < o.n
	case "ge":
		ok = f >= o.n
	case "le":
		ok = f <= o.n
	}
	if ok {
		return 0, len(v), true
	}
	return 0, 0, false
}
func (o *cmpOp) Name() string    { return o.cmp }
func (o *cmpOp) hints() [][]byte { return nil }

func splitCmp(s string) (cmp, num string) {
	s = strings.TrimSpace(s)
	for _, c := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(s, c) {
			return c, strings.TrimSpace(s[len(c):])
		}
	}
	return ">", s
}

func compareInt(a int, cmp string, b int) bool {
	switch cmp {
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	case "=", "==":
		return a == b
	case "!=":
		return a != b
	}
	return a > b
}

// --- regexp (RE2, linear time) ---

type rxOp struct {
	re   *regexp.Regexp
	hint [][]byte
}

func newRxOp(pat string) (Operator, error) {
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("bad regexp: %w", err)
	}
	re.Longest()
	return &rxOp{re: re, hint: rxHints(pat)}, nil
}

func (o *rxOp) Match(v []byte) (int, int, bool) {
	loc := o.re.FindIndex(v)
	if loc == nil {
		return 0, 0, false
	}
	return loc[0], loc[1], true
}
func (o *rxOp) Name() string    { return "rx" }
func (o *rxOp) hints() [][]byte { return o.hint }

// rxHints pulls a required literal substring out of a regex so the
// prefilter can skip rules whose literal is absent. Returns nil when the
// pattern has no guaranteed literal (alternation at the top, etc).
func rxHints(pat string) [][]byte {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	lit := requiredLiteral(re)
	if len(lit) < 3 {
		return nil
	}
	return [][]byte{[]byte(strings.ToLower(lit))}
}

// requiredLiteral finds the longest literal that must appear. Only handles
// concat and single-child cases; alternation yields nothing (unsound to
// pick one branch).
func requiredLiteral(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpConcat:
		best := ""
		cur := ""
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				cur += string(sub.Rune)
				if len(cur) > len(best) {
					best = cur
				}
			} else {
				cur = ""
			}
		}
		return best
	case syntax.OpCapture:
		return requiredLiteral(re.Sub[0])
	case syntax.OpPlus:
		return requiredLiteral(re.Sub[0])
	}
	return ""
}

// --- multi-pattern (aho-corasick) ---

type pmOp struct {
	m     *ac.Matcher
	first []byte
}

func newPMOp(arg string, load dataLoader, fromFile bool) (Operator, error) {
	var pats [][]byte
	if fromFile || strings.HasPrefix(arg, "@") {
		path := strings.TrimPrefix(arg, "@")
		lines, err := load(path)
		if err != nil {
			return nil, err
		}
		pats = lines
	} else {
		for _, w := range splitList(arg) {
			pats = append(pats, []byte(w))
		}
	}
	if len(pats) == 0 {
		return nil, fmt.Errorf("pm: no patterns in %q", arg)
	}
	m, err := ac.Compile(pats, true)
	if err != nil {
		return nil, err
	}
	return &pmOp{m: m}, nil
}

func (o *pmOp) Match(v []byte) (int, int, bool) {
	id, end, ok := o.m.Find(v)
	if !ok {
		return 0, 0, false
	}
	return end - len(o.m.Pattern(id)), end, true
}
func (o *pmOp) Name() string    { return "pm" }
func (o *pmOp) hints() [][]byte { return nil } // the matcher is its own prefilter

// --- detectors backed by the operator subpackages ---

type sqliOp struct{}

func (sqliOp) Match(v []byte) (int, int, bool) {
	r, ok := sqli.Detect(v)
	return r.Start, r.End, ok
}
func (sqliOp) Name() string    { return "sqli" }
func (sqliOp) hints() [][]byte { return nil }

type xssOp struct{}

func (xssOp) Match(v []byte) (int, int, bool) {
	r, ok := xss.Detect(v)
	return r.Start, r.End, ok
}
func (xssOp) Name() string    { return "xss" }
func (xssOp) hints() [][]byte { return nil }

type pathOp struct{}

func (pathOp) Match(v []byte) (int, int, bool) {
	m, ok := pathnorm.Detect(v)
	return m.Start, m.End, ok
}
func (pathOp) Name() string    { return "detectpath" }
func (pathOp) hints() [][]byte { return nil }

type xxeOp struct{}

// detectxxe works off the pre-extracted XMLInfo the tx carries, so as an
// operator over a value it just checks for the doctype+entity+system shape
// in the raw bytes. The tx short-circuits to the info when it has it.
func (xxeOp) Match(v []byte) (int, int, bool) {
	low := bytes.ToLower(v)
	if bytes.Contains(low, []byte("<!doctype")) && bytes.Contains(low, []byte("<!entity")) &&
		(bytes.Contains(low, []byte("system")) || bytes.Contains(low, []byte("public"))) {
		return 0, len(v), true
	}
	if bytes.Contains(low, []byte(":include")) {
		return 0, len(v), true
	}
	return 0, 0, false
}
func (xxeOp) Name() string    { return "detectxxe" }
func (xxeOp) hints() [][]byte { return nil }

type shellOp struct{ cmds *ac.Matcher }

func newShellOp(arg string, load dataLoader) (Operator, error) {
	path := strings.TrimPrefix(arg, "@")
	lines, err := load(path)
	if err != nil {
		return nil, err
	}
	m, err := ac.Compile(lines, true)
	if err != nil {
		return nil, err
	}
	return &shellOp{cmds: m}, nil
}

// Match wants a real shell metachar before the command word (spaces in
// between are fine), so an actual command breakout like "; cat" or "$(id)"
// trips but ordinary prose ("meet me at noon", "drop off the kids") does
// not, since a bare word with no metachar cannot break out of a command.
func (o *shellOp) Match(v []byte) (int, int, bool) {
	hit := false
	var s, e int
	o.cmds.Each(v, func(id, end int) bool {
		start := end - len(o.cmds.Pattern(id))
		// right boundary: the command must not be part of a longer word
		if end < len(v) && isWordByte(v[end]) {
			return true
		}
		if start > 0 && isWordByte(v[start-1]) {
			return true
		}
		// scan left over spaces, then require a shell metachar
		i := start - 1
		for i >= 0 && (v[i] == ' ' || v[i] == '\t') {
			i--
		}
		if i < 0 {
			return true // no metachar before it, not a breakout
		}
		switch v[i] {
		case ';', '|', '&', '`', '(', '$', '\n', '{':
			s, e, hit = start, end, true
			return false
		}
		return true
	})
	return s, e, hit
}
func (o *shellOp) Name() string    { return "shellcmd" }
func (o *shellOp) hints() [][]byte { return nil }

type ssrfOp struct{}

func (ssrfOp) Match(v []byte) (int, int, bool) {
	return ssrfDetect(v)
}
func (ssrfOp) Name() string    { return "ssrfhost" }
func (ssrfOp) hints() [][]byte { return nil }

type jndiOp struct{}

func (jndiOp) Match(v []byte) (int, int, bool) {
	return jndiDetect(v)
}
func (jndiOp) Name() string    { return "jndi" }
func (jndiOp) hints() [][]byte { return nil }

type byteRangeOp struct{ allow [256]bool }

func newByteRangeOp(arg string) (Operator, error) {
	o := &byteRangeOp{}
	for _, part := range strings.Split(arg, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, ok := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("byterange: %q", part)
		}
		b := a
		if ok {
			b, err = strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("byterange: %q", part)
			}
		}
		for i := a; i <= b && i < 256; i++ {
			o.allow[i] = true
		}
	}
	return o, nil
}

// Match reports the first byte OUTSIDE the allowed set (used with negate to
// say "all bytes must be in range").
func (o *byteRangeOp) Match(v []byte) (int, int, bool) {
	for i, c := range v {
		if !o.allow[c] {
			return i, i + 1, true
		}
	}
	return 0, 0, false
}
func (o *byteRangeOp) Name() string    { return "byterange" }
func (o *byteRangeOp) hints() [][]byte { return nil }

type validUTF8Op struct{}

// Match reports the first invalid utf8 byte.
func (validUTF8Op) Match(v []byte) (int, int, bool) {
	for i := 0; i < len(v); {
		if v[i] < 0x80 {
			i++
			continue
		}
		r, size := utf8.DecodeRune(v[i:])
		if r == utf8.RuneError && size <= 1 {
			return i, i + 1, true
		}
		i += size
	}
	return 0, 0, false
}
func (validUTF8Op) Name() string    { return "validutf8" }
func (validUTF8Op) hints() [][]byte { return nil }

type uncondOp struct{}

func (uncondOp) Match(v []byte) (int, int, bool) { return 0, len(v), true }
func (uncondOp) Name() string                    { return "unconditional" }
func (uncondOp) hints() [][]byte                 { return nil }

// ssrfDetect finds urls whose host is internal, loopback, link-local or a
// cloud metadata endpoint, parsing the odd ip encodings attackers use.
func ssrfDetect(v []byte) (int, int, bool) {
	s := strings.ToLower(string(v))
	metaNames := []string{"metadata.google.internal", "metadata.google", "metadata.azure", "169.254.169.254", "100.100.100.200", "metadata.oraclecloud"}
	for _, m := range metaNames {
		if i := strings.Index(s, m); i >= 0 {
			return i, i + len(m), true
		}
	}
	// scheme then host
	for _, sch := range []string{"http://", "https://", "gopher://", "dict://", "ftp://", "file://", "ldap://"} {
		i := 0
		for {
			j := strings.Index(s[i:], sch)
			if j < 0 {
				break
			}
			j += i
			host := hostOf(s[j+len(sch):])
			if sch == "file://" {
				return j, j + len(sch), true
			}
			if isInternalHost(host) {
				return j, j + len(sch) + len(host), true
			}
			i = j + len(sch)
		}
	}
	return 0, 0, false
}

func hostOf(s string) string {
	// stop at /, :, ?, #, @, or whitespace, but keep [::1]
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end >= 0 {
			return s[:end+1]
		}
	}
	// user@host: take the part after the last @ before the first path sep
	end := len(s)
	for i, c := range []byte(s) {
		if c == '/' || c == '?' || c == '#' || c == ' ' {
			end = i
			break
		}
	}
	h := s[:end]
	if at := strings.LastIndexByte(h, '@'); at >= 0 {
		h = h[at+1:]
	}
	if c := strings.IndexByte(h, ':'); c >= 0 && !strings.HasPrefix(h, "[") {
		h = h[:c]
	}
	return h
}

func isInternalHost(h string) bool {
	h = strings.Trim(h, "[]")
	switch h {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1", "0", "127.1":
		return true
	}
	if strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".local") {
		return true
	}
	if ip := parseWeirdIP(h); ip.IsValid() {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsUnspecified() || (ip.Is4() && ip.As4()[0] == 100 && ip.As4()[1] >= 64 && ip.As4()[1] <= 127)
	}
	return false
}

// parseWeirdIP handles decimal (2130706433), octal (0177.0.0.1), hex
// (0x7f000001) and short (127.1) forms in addition to the normal ones.
func parseWeirdIP(h string) netip.Addr {
	if a, err := netip.ParseAddr(h); err == nil {
		return a
	}
	// pure decimal
	if n, err := strconv.ParseUint(h, 10, 64); err == nil && n <= 0xFFFFFFFF {
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
	// 0x hex whole
	if strings.HasPrefix(h, "0x") {
		if n, err := strconv.ParseUint(h[2:], 16, 64); err == nil && n <= 0xFFFFFFFF {
			return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
		}
	}
	// dotted with octal/hex/short parts
	parts := strings.Split(h, ".")
	if len(parts) >= 2 && len(parts) <= 4 {
		var octs [4]uint64
		ok := true
		for i, p := range parts {
			var base = 10
			if strings.HasPrefix(p, "0x") {
				base, p = 16, p[2:]
			} else if len(p) > 1 && p[0] == '0' {
				base = 8
			}
			n, err := strconv.ParseUint(p, base, 64)
			if err != nil {
				ok = false
				break
			}
			octs[i] = n
		}
		if ok {
			// 127.1 -> 127.0.0.1 (last part fills remaining octets)
			switch len(parts) {
			case 2:
				if octs[0] <= 255 && octs[1] <= 0xFFFFFF {
					return netip.AddrFrom4([4]byte{byte(octs[0]), byte(octs[1] >> 16), byte(octs[1] >> 8), byte(octs[1])})
				}
			case 3:
				if octs[0] <= 255 && octs[1] <= 255 && octs[2] <= 0xFFFF {
					return netip.AddrFrom4([4]byte{byte(octs[0]), byte(octs[1]), byte(octs[2] >> 8), byte(octs[2])})
				}
			case 4:
				if octs[0] <= 255 && octs[1] <= 255 && octs[2] <= 255 && octs[3] <= 255 {
					return netip.AddrFrom4([4]byte{byte(octs[0]), byte(octs[1]), byte(octs[2]), byte(octs[3])})
				}
			}
		}
	}
	return netip.Addr{}
}

// jndiDetect canonicalizes ${...} lookup nesting then looks for the
// log4shell protocols.
func jndiDetect(v []byte) (int, int, bool) {
	s := strings.ToLower(string(v))
	if !strings.Contains(s, "${") && !strings.Contains(s, "jndi") {
		return 0, 0, false
	}
	// strip the lookup wrappers log4j resolves: ${lower:x} ${::-x} ${env:x}
	clean := s
	for _, junk := range []string{"${lower:", "${upper:", "${::-", "${env:", "${sys:", "${date:", "${java:", "${main:", "${", "}", ":-"} {
		clean = strings.ReplaceAll(clean, junk, "")
	}
	for _, proto := range []string{"jndi:ldap", "jndi:ldaps", "jndi:rmi", "jndi:dns", "jndi:iiop", "jndi:corba", "jndi:nis", "jndi:nds", "jndi:http"} {
		if strings.Contains(clean, proto) {
			i := strings.Index(s, "jndi")
			if i < 0 {
				i = 0
			}
			return i, min(i+16, len(v)), true
		}
	}
	return 0, 0, false
}
