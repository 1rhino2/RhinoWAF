// Package ac is an Aho-Corasick matcher with the failure links resolved
// into a full DFA at build time, so scanning is one table lookup per byte
// with no failure loop. The alphabet is compressed to the bytes that
// actually occur in the pattern set (a keyword list uses maybe 40 of the
// 256), which keeps a 1500-pattern automaton around a couple of MB.
//
// Used two ways: as the "pm" operator over data lists, and as the per-phase
// prefilter that decides which rules are even worth running on a value.
package ac

import (
	"errors"
	"sort"
)

type Matcher struct {
	delta    []int32   // states x width
	out      [][]int32 // pattern ids ending at state (after failure merge)
	alpha    [256]uint8
	width    int
	patterns [][]byte
	ci       bool
}

// Compile builds the automaton. Empty patterns are rejected, duplicates
// are kept (they just report both ids).
func Compile(patterns [][]byte, caseInsensitive bool) (*Matcher, error) {
	if len(patterns) == 0 {
		return nil, errors.New("ac: no patterns")
	}
	m := &Matcher{ci: caseInsensitive, patterns: make([][]byte, len(patterns))}

	// alphabet: symbol 0 is "any byte not in a pattern"
	var seen [256]bool
	for i, p := range patterns {
		if len(p) == 0 {
			return nil, errors.New("ac: empty pattern")
		}
		q := make([]byte, len(p))
		for j, c := range p {
			if caseInsensitive {
				c = fold(c)
			}
			q[j] = c
			seen[c] = true
		}
		m.patterns[i] = q
	}
	sym := uint8(1)
	for c := 0; c < 256; c++ {
		if seen[c] {
			m.alpha[c] = sym
			sym++
		}
	}
	if caseInsensitive {
		for c := 'A'; c <= 'Z'; c++ {
			m.alpha[c] = m.alpha[c+'a'-'A']
		}
	}
	m.width = int(sym)

	// trie
	type node struct {
		next []int32
		out  []int32
	}
	nodes := []node{{next: make([]int32, m.width)}}
	for i := range nodes[0].next {
		nodes[0].next[i] = -1
	}
	for id, p := range m.patterns {
		cur := int32(0)
		for _, c := range p {
			s := m.alpha[c]
			if nodes[cur].next[s] < 0 {
				n := node{next: make([]int32, m.width)}
				for i := range n.next {
					n.next[i] = -1
				}
				nodes = append(nodes, n)
				nodes[cur].next[s] = int32(len(nodes) - 1)
			}
			cur = nodes[cur].next[s]
		}
		nodes[cur].out = append(nodes[cur].out, int32(id))
	}

	// bfs for failure links, resolve missing edges to the failure target so
	// the runtime never follows a failure chain
	fail := make([]int32, len(nodes))
	queue := make([]int32, 0, len(nodes))
	for s := 0; s < m.width; s++ {
		if n := nodes[0].next[s]; n >= 0 {
			fail[n] = 0
			queue = append(queue, n)
		} else {
			nodes[0].next[s] = 0
		}
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for s := 0; s < m.width; s++ {
			v := nodes[u].next[s]
			if v < 0 {
				nodes[u].next[s] = nodes[fail[u]].next[s]
				continue
			}
			f := nodes[fail[u]].next[s]
			fail[v] = f
			nodes[v].out = append(nodes[v].out, nodes[f].out...)
			queue = append(queue, v)
		}
	}

	m.delta = make([]int32, len(nodes)*m.width)
	m.out = make([][]int32, len(nodes))
	for i, n := range nodes {
		copy(m.delta[i*m.width:], n.next)
		if len(n.out) > 0 {
			sort.Slice(n.out, func(a, b int) bool { return n.out[a] < n.out[b] })
			m.out[i] = n.out
		}
	}
	return m, nil
}

func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// Find returns the first pattern that finishes matching, and the index one
// past its last byte. Leftmost end, so the shortest-ending match wins.
func (m *Matcher) Find(text []byte) (patIdx, end int, ok bool) {
	state := int32(0)
	w := m.width
	for i, c := range text {
		state = m.delta[int(state)*w+int(m.alpha[c])]
		if o := m.out[state]; len(o) > 0 {
			return int(o[0]), i + 1, true
		}
	}
	return 0, 0, false
}

// Each reports every match. fn returns false to stop early.
func (m *Matcher) Each(text []byte, fn func(patIdx, end int) bool) {
	state := int32(0)
	w := m.width
	for i, c := range text {
		state = m.delta[int(state)*w+int(m.alpha[c])]
		for _, id := range m.out[state] {
			if !fn(int(id), i+1) {
				return
			}
		}
	}
}

// Pattern returns the (case folded) pattern by id.
func (m *Matcher) Pattern(i int) []byte { return m.patterns[i] }

func (m *Matcher) Len() int { return len(m.patterns) }

// States is for the stats endpoint and the memory sanity test.
func (m *Matcher) States() int { return len(m.out) }
