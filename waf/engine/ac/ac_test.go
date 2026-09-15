package ac

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func pats(s ...string) [][]byte {
	out := make([][]byte, len(s))
	for i, x := range s {
		out[i] = []byte(x)
	}
	return out
}

func TestBasic(t *testing.T) {
	m, err := Compile(pats("he", "she", "his", "hers"), false)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	m.Each([]byte("ushers"), func(id, end int) bool {
		got = append(got, fmt.Sprintf("%s@%d", m.Pattern(id), end))
		return true
	})
	want := "he@4 she@4 hers@6"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %q want %q", strings.Join(got, " "), want)
	}
	id, end, ok := m.Find([]byte("xxhisxx"))
	if !ok || string(m.Pattern(id)) != "his" || end != 5 {
		t.Fatalf("find: %v %d %v", id, end, ok)
	}
	if _, _, ok := m.Find([]byte("xyz")); ok {
		t.Fatal("false match")
	}
}

func TestCaseInsensitive(t *testing.T) {
	m, _ := Compile(pats("SeLeCt", "union"), true)
	for _, s := range []string{"select", "SELECT", "xUNIONx", "Union"} {
		if _, _, ok := m.Find([]byte(s)); !ok {
			t.Errorf("miss %q", s)
		}
	}
	mc, _ := Compile(pats("Select"), false)
	if _, _, ok := mc.Find([]byte("select")); ok {
		t.Error("case sensitive matched wrong case")
	}
}

func TestErrors(t *testing.T) {
	if _, err := Compile(nil, false); err == nil {
		t.Error("nil patterns accepted")
	}
	if _, err := Compile(pats("a", ""), false); err == nil {
		t.Error("empty pattern accepted")
	}
}

func TestBinaryAndOverlap(t *testing.T) {
	m, _ := Compile([][]byte{{0x00, 0xff}, {0xff, 0xff}, []byte("aaa")}, false)
	n := 0
	m.Each([]byte{0x00, 0xff, 0xff, 'a', 'a', 'a', 'a'}, func(int, int) bool { n++; return true })
	// 00ff@2, ffff@3, aaa@6, aaa@7
	if n != 4 {
		t.Fatalf("overlap count %d", n)
	}
}

// compare against the naive search on random inputs
func TestAgainstNaive(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("abcd")
	for iter := 0; iter < 300; iter++ {
		var ps [][]byte
		np := 1 + rng.Intn(8)
		for i := 0; i < np; i++ {
			l := 1 + rng.Intn(4)
			p := make([]byte, l)
			for j := range p {
				p[j] = alphabet[rng.Intn(len(alphabet))]
			}
			ps = append(ps, p)
		}
		text := make([]byte, rng.Intn(60))
		for j := range text {
			text[j] = alphabet[rng.Intn(len(alphabet)+1)%len(alphabet)]
		}
		m, err := Compile(ps, false)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		m.Each(text, func(id, end int) bool {
			got = append(got, fmt.Sprintf("%d@%d", id, end))
			return true
		})
		var want []string
		for end := 1; end <= len(text); end++ {
			for id, p := range ps {
				if end >= len(p) && bytes.Equal(text[end-len(p):end], p) {
					want = append(want, fmt.Sprintf("%d@%d", id, end))
				}
			}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("iter %d: patterns %q text %q\n got %v\nwant %v", iter, ps, text, got, want)
		}
	}
}

func TestEarlyStop(t *testing.T) {
	m, _ := Compile(pats("a"), false)
	n := 0
	m.Each([]byte("aaaa"), func(int, int) bool { n++; return false })
	if n != 1 {
		t.Fatalf("stop ignored: %d", n)
	}
}

func TestBigListMemory(t *testing.T) {
	var ps [][]byte
	for i := 0; i < 1500; i++ {
		ps = append(ps, []byte(fmt.Sprintf("keyword_%d_xx", i)))
	}
	m, err := Compile(ps, true)
	if err != nil {
		t.Fatal(err)
	}
	bytesUsed := len(m.delta) * 4
	if bytesUsed > 8<<20 {
		t.Fatalf("automaton too big: %d bytes for %d states", bytesUsed, m.States())
	}
	if id, _, ok := m.Find([]byte("...KEYWORD_1234_XX...")); !ok || id != 1234 {
		t.Fatalf("big list find: %d %v", id, ok)
	}
}

func FuzzFind(f *testing.F) {
	f.Add("abc,bcd,cde", "xxabcdexx")
	f.Add("a", "")
	f.Fuzz(func(t *testing.T, plist, text string) {
		var ps [][]byte
		for _, p := range strings.Split(plist, ",") {
			if p != "" {
				ps = append(ps, []byte(p))
			}
		}
		if len(ps) == 0 {
			return
		}
		m, err := Compile(ps, false)
		if err != nil {
			t.Fatal(err)
		}
		id, end, ok := m.Find([]byte(text))
		if ok {
			p := m.Pattern(id)
			if end < len(p) || !bytes.Equal([]byte(text)[end-len(p):end], p) {
				t.Fatalf("bogus match %q at %d in %q", p, end, text)
			}
		} else {
			for _, p := range ps {
				if bytes.Contains([]byte(text), p) {
					t.Fatalf("missed %q in %q", p, text)
				}
			}
		}
	})
}

func BenchmarkFind500(b *testing.B) {
	var ps [][]byte
	for i := 0; i < 500; i++ {
		ps = append(ps, []byte(fmt.Sprintf("kw%dabc", i)))
	}
	m, _ := Compile(ps, true)
	text := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), 20)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Find(text)
	}
}
