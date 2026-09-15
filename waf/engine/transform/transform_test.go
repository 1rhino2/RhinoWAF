package transform

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func run(t *testing.T, id ID, in string) string {
	t.Helper()
	return string(Apply(id, nil, []byte(in)))
}

func TestURLDecode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a+b%20c", "a b c"},
		{"%3Cscript%3E", "<script>"},
		{"%zz%2", "%zz%2"}, // bad escapes stay
		{"%252e", "%2e"},   // single pass only
		{"100%", "100%"},
		{"%u003c", "%u003c"}, // plain urldecode ignores %u
	}
	for _, c := range cases {
		if got := run(t, URLDecode, c.in); got != c.want {
			t.Errorf("urldecode(%q)=%q want %q", c.in, got, c.want)
		}
	}
	uni := []struct{ in, want string }{
		{"%u003cscript", "<script"},
		{"%uFF1Cscript", "<script"}, // fullwidth < folds
		{"%u00e9", "é"},
		{"%uZZZZ", "%uZZZZ"},
	}
	for _, c := range uni {
		if got := run(t, URLDecodeUni, c.in); got != c.want {
			t.Errorf("urldecode_uni(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestHTMLDecode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"&lt;script&gt;", "<script>"},
		{"&#60;script&#62;", "<script>"},
		{"&#x3c;script", "<script"},
		{"&#0000060;", "<"},
		{"&#60script", "<script"}, // no semicolon, browsers still decode
		{"&#X3C;", "<"},
		{"&amp;lt;", "&lt;"}, // single pass
		{"no entities", "no entities"},
		{"&#;", "&#;"},
		{"&#0;", "�"},
		{"&#99999999999999;", "�"},
		{"a &b c", "a &b c"},
	}
	for _, c := range cases {
		if got := run(t, HTMLDecode, c.in); got != c.want {
			t.Errorf("htmldecode(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestJSDecode(t *testing.T) {
	cases := []struct{ in, want string }{
		{`\x3cscript\x3e`, "<script>"},
		{`<script>`, "<script>"},
		{`\u{3c}b`, "<b"},
		{`\74script`, "<script"},
		{`a\nb\tc`, "a\nb\tc"},
		{`\\`, `\`},
		{`\q`, "q"},
		{`\x3`, `\x3`},
		{`\u12`, `\u12`},
		{`trailing\`, `trailing\`},
	}
	for _, c := range cases {
		if got := run(t, JSDecode, c.in); got != c.want {
			t.Errorf("jsdecode(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestCSSDecode(t *testing.T) {
	cases := []struct{ in, want string }{
		{`\3c script`, "<script"},
		{`\00003cscript`, "<script"},
		{`\"`, `"`},
		{`expr\65 ssion(`, "expression("},
	}
	for _, c := range cases {
		if got := run(t, CSSDecode, c.in); got != c.want {
			t.Errorf("cssdecode(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestUTF8Normalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"caf\xc3\xa9", "café"},
		{"\xc0\xae", "��"}, // overlong dot
		{"\xff", "�"},
		{"\xe2\x82", "��"}, // truncated
	}
	for _, c := range cases {
		got := run(t, UTF8Normalize, c.in)
		if got != c.want || !utf8.ValidString(got) {
			t.Errorf("utf8(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestWhitespaceAndNulls(t *testing.T) {
	if got := run(t, CompressWS, "a \t\n b   c"); got != "a b c" {
		t.Errorf("compress: %q", got)
	}
	if got := run(t, RemoveWS, "a \t b"); got != "ab" {
		t.Errorf("remove ws: %q", got)
	}
	if got := run(t, RemoveNulls, "a\x00b"); got != "ab" {
		t.Errorf("nulls: %q", got)
	}
	if got := run(t, Trim, "  x y \n"); got != "x y" {
		t.Errorf("trim: %q", got)
	}
	if got := run(t, Lowercase, "AbC É"); got != "abc É" {
		t.Errorf("lower: %q", got)
	}
}

func TestRemoveComments(t *testing.T) {
	cases := []struct{ in, want, wantChar string }{
		{"un/**/ion", "un ion", "union"},
		{"1' or 1=1 -- x", "1' or 1=1  ", "1' or 1=1  x"},
		{"a#b\nc", "a c", "ab\nc"},
		{"/* open", " ", " open"},
		{"x /*a*/ /*b*/ y", "x     y", "x   y"},
		{"clean", "clean", "clean"},
	}
	for _, c := range cases {
		if got := run(t, RemoveComments, c.in); got != c.want {
			t.Errorf("remove_comments(%q)=%q want %q", c.in, got, c.want)
		}
		if got := run(t, RemoveCommentsChar, c.in); got != c.wantChar {
			t.Errorf("remove_comments_char(%q)=%q want %q", c.in, got, c.wantChar)
		}
	}
}

func TestBase64(t *testing.T) {
	if got := run(t, Base64Decode, "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="); got != "<script>alert(1)</script>" {
		t.Errorf("b64: %q", got)
	}
	if got := run(t, Base64Decode, "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg"); got != "<script>alert(1)</script>" {
		t.Errorf("b64 nopad: %q", got)
	}
	// url safe alphabet
	if got := run(t, Base64Decode, "Pz8_Pz8_Pz8_Pz8_Pz8_"); got != "???????????????" {
		t.Errorf("b64url: %q", got)
	}
	for _, s := range []string{"hello world", "short", "abc=def", "a=b=c=d=e=f=g=h=", "not base64 at all!!"} {
		if got := run(t, Base64Decode, s); got != s {
			t.Errorf("b64 should pass through %q, got %q", s, got)
		}
	}
	if !Base64Shaped([]byte("eyJhbGciOiJIUzI1NiJ9")) {
		t.Error("jwt header segment should be base64 shaped")
	}
}

func TestHex(t *testing.T) {
	if got := run(t, HexDecode, "3c7363726970743e"); got != "<script>" {
		t.Errorf("hex: %q", got)
	}
	for _, s := range []string{"abc", "zz", "", "12 34"} {
		if got := run(t, HexDecode, s); got != s {
			t.Errorf("hex passthrough %q -> %q", s, got)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/a/./b/../c", "/a/c"},
		{"/a//b///c/", "/a/b/c/"},
		{"/../../etc/passwd", "/etc/passwd"},
		{"a/../../b", "b"},
		{"/", "/"},
		{"", ""},
		{"/a/b/", "/a/b/"},
	}
	for _, c := range cases {
		if got := run(t, NormalizePath, c.in); got != c.want {
			t.Errorf("normalize_path(%q)=%q want %q", c.in, got, c.want)
		}
	}
	if got := run(t, NormalizePathWin, `\a\..\b\c`); got != "/b/c" {
		t.Errorf("win: %q", got)
	}
}

func TestCmdLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{`c'a't /etc/passwd`, "cat/etc/passwd"},
		{`c^a^t   / etc / passwd`, "cat/ etc/ passwd"},
		{`CAT "x"`, "cat x"},
		{`ls ( -la )`, "ls( -la )"},
		{`  id  `, "id"},
		{`a;b,c`, "a b c"},
	}
	for _, c := range cases {
		if got := run(t, CmdLine, c.in); got != c.want {
			t.Errorf("cmdline(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestParseChain(t *testing.T) {
	ch, err := ParseChain([]string{"urldecode", " lower", "remove_comments", ""})
	if err != nil || len(ch) != 3 || ch[0] != URLDecode || ch[1] != Lowercase || ch[2] != RemoveComments {
		t.Fatalf("chain: %v %v", ch, err)
	}
	if _, err := ParseChain([]string{"nope"}); err == nil {
		t.Fatal("unknown transform accepted")
	}
	for id := ID(1); id < maxID; id++ {
		if id.String() == "" {
			t.Errorf("id %d has no name", id)
		}
		if back, err := Parse(id.String()); err != nil || back != id {
			t.Errorf("name round trip for %d: %q", id, id.String())
		}
	}
}

func TestRunChainAndCache(t *testing.T) {
	chain := []ID{URLDecode, Lowercase, RemoveCommentsChar}
	out, _, _ := Run(chain, []byte("UNI%2f**%2fON%20SELECT"), nil, nil)
	if string(out) != "union select" {
		t.Fatalf("chain out %q", out)
	}
	c := NewCache()
	a := c.Get(1, 7, chain, []byte("A%20B"), 0)
	b := c.Get(1, 7, chain, []byte("ignored, cached"), 0)
	if string(a) != "a b" || string(b) != "a b" {
		t.Fatalf("cache: %q %q", a, b)
	}
	if got := c.Get(2, 7, chain, []byte("C"), 0); string(got) != "c" {
		t.Fatalf("other value: %q", got)
	}
	if got := c.Get(3, 7, chain, []byte("abcdefgh"), 3); string(got) != "abc" {
		t.Fatalf("maxOut: %q", got)
	}
	// the first result must still read right after the arena grew
	big := bytes.Repeat([]byte("x"), 20000)
	_ = c.Get(4, 7, chain, big, 0)
	if string(a) != "a b" {
		t.Fatal("earlier slice corrupted by growth")
	}
	c.Reset()
	if len(c.idx) != 0 {
		t.Fatal("reset kept entries")
	}
}

func TestApplyNeverAliasesInput(t *testing.T) {
	src := []byte("Hello%20World")
	for id := ID(0); id < maxID; id++ {
		out := Apply(id, nil, src)
		if len(out) > 0 && len(src) > 0 && &out[0] == &src[0] {
			t.Errorf("transform %v returned the input slice", id)
		}
	}
}

// property: every transform is bounded and safe on arbitrary bytes
func FuzzApply(f *testing.F) {
	seeds := []string{"", "%", "%u", "%uFF1C", "&#", "&#x", `\`, `\u{`, "/*", "--", "..", "/a/../..", "\xc0\xae", "+", "PHNjcmlwdD4="}
	for _, s := range seeds {
		for id := ID(0); id < maxID; id++ {
			f.Add(uint8(id), s)
		}
	}
	f.Fuzz(func(t *testing.T, idb uint8, in string) {
		id := ID(idb % uint8(maxID))
		out := Apply(id, nil, []byte(in))
		if len(out) > 3*len(in)+3 {
			t.Fatalf("transform %v grew %d -> %d", id, len(in), len(out))
		}
		if id == UTF8Normalize && !utf8.Valid(out) {
			t.Fatalf("utf8normalize produced invalid utf8 from %q", in)
		}
		// applying twice must not panic either, and decoders converge
		Apply(id, nil, out)
	})
}
