package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"rhinowaf/waf/engine/ac"
	"rhinowaf/waf/engine/rulefile"
	"rhinowaf/waf/engine/transform"
)

// Ruleset is the compiled, immutable form the engine evaluates. Swapped
// atomically on reload.
type Ruleset struct {
	rules     []*Rule
	byID      map[int]*Rule
	chains    [][]transform.ID // chain table, index is ChainID
	byPhase   map[Phase][]*Rule
	prefilter map[Phase]*prefilter
	hash      string
	counts    map[string]int // category -> count, for stats
	maxPL     uint8
}

// prefilter maps a value (viewed through urldecode+lower) to the set of
// candidate rule ordinals via one aho-corasick pass over all hint literals.
type prefilter struct {
	m      *ac.Matcher
	hintOf []int // pattern id -> owning rule ordinal
	always []int // rule ordinals with no usable hint, always run
}

// Compile turns parsed files into a Ruleset. Later files layer over earlier
// ones (add rules, or disable/override/exclude via directives).
func compile(files []*rulefile.File, load dataLoader) (*Ruleset, error) {
	rs := &Ruleset{
		byID:      map[int]*Rule{},
		byPhase:   map[Phase][]*Rule{},
		prefilter: map[Phase]*prefilter{},
		counts:    map[string]int{},
	}
	chainIndex := map[string]int{}
	getChain := func(ids []transform.ID) int {
		key := chainKey(ids)
		if id, ok := chainIndex[key]; ok {
			return id
		}
		id := len(rs.chains)
		rs.chains = append(rs.chains, ids)
		chainIndex[key] = id
		return id
	}

	var hashParts []string
	for _, f := range files {
		for i := range f.Rules {
			r, err := compileRule(&f.Rules[i], load, getChain)
			if err != nil {
				return nil, err
			}
			if _, dup := rs.byID[r.ID]; dup {
				return nil, fmt.Errorf("duplicate rule id %d", r.ID)
			}
			rs.byID[r.ID] = r
			rs.rules = append(rs.rules, r)
			hashParts = append(hashParts, fmt.Sprintf("%d:%s:%d", r.ID, r.Category, r.Score))
		}
	}
	// directives from every file, applied after all rules exist
	for _, f := range files {
		for _, d := range f.Directives {
			applyDirective(rs, d)
		}
	}

	// assign ordinals, bucket by phase, count, build prefilter
	sort.Slice(rs.rules, func(a, b int) bool { return rs.rules[a].ID < rs.rules[b].ID })
	for i, r := range rs.rules {
		r.ordinal = i
		rs.byPhase[r.Phase] = append(rs.byPhase[r.Phase], r)
		rs.counts[r.Category]++
		if r.Paranoia > rs.maxPL {
			rs.maxPL = r.Paranoia
		}
	}
	for ph, rules := range rs.byPhase {
		rs.prefilter[ph] = buildPrefilter(rules)
	}
	sum := sha256.Sum256([]byte(strings.Join(hashParts, "|")))
	rs.hash = hex.EncodeToString(sum[:8])
	return rs, nil
}

func chainKey(ids []transform.ID) string {
	b := make([]byte, len(ids))
	for i, id := range ids {
		b[i] = byte(id)
	}
	return string(b)
}

func compileRule(pr *rulefile.Rule, load dataLoader, getChain func([]transform.ID) int) (*Rule, error) {
	r := &Rule{
		ID:       pr.ID,
		Name:     pr.Name,
		Category: pr.Category,
		Paranoia: uint8(pr.Paranoia),
		Tags:     pr.Tags,
	}
	if r.Paranoia == 0 {
		r.Paranoia = 1
	}
	sev, err := parseSeverity(orDefault(pr.Severity, "warning"))
	if err != nil {
		return nil, fmt.Errorf("rule %d: %w", pr.ID, err)
	}
	r.Severity = sev
	r.Score = int(sev)
	if pr.Score != nil {
		r.Score = *pr.Score
	}
	if r.Phase, err = parsePhase(orDefault(pr.Phase, "request-body")); err != nil {
		return nil, fmt.Errorf("rule %d: %w", pr.ID, err)
	}
	if r.Action, err = parseAction(pr.Action); err != nil {
		return nil, fmt.Errorf("rule %d: %w", pr.ID, err)
	}
	if r.Mode, err = parseMode(pr.Mode); err != nil {
		return nil, fmt.Errorf("rule %d: %w", pr.ID, err)
	}

	primary, err := compileCond(pr.Targets, pr.Excludes, pr.Transforms, pr.Op, pr.OpArg, pr.Negate, pr.SkipOpaque, load, getChain)
	if err != nil {
		return nil, fmt.Errorf("rule %d: %w", pr.ID, err)
	}
	r.Conds = append(r.Conds, primary)
	for _, pc := range pr.Conds {
		c, err := compileCond(pc.Targets, pc.Excludes, pc.Transforms, pc.Op, pc.OpArg, pc.Negate, pc.SkipOpaque, load, getChain)
		if err != nil {
			return nil, fmt.Errorf("rule %d cond: %w", pr.ID, err)
		}
		if len(c.Targets) == 0 {
			c.Targets = primary.Targets
		}
		r.Conds = append(r.Conds, c)
	}

	// prefilter hints: only sound when the chain ends the way the prefilter
	// view does (urldecode then lower), otherwise the literal might not be
	// present in the prefiltered form.
	if h := primary.Op.hints(); len(h) > 0 && chainCompatible(primary.Chain) {
		r.Hints = h
	}
	return r, nil
}

func compileCond(targets, excludes, transforms []string, op, opArg string, negate, skip bool, load dataLoader, getChain func([]transform.ID) int) (Cond, error) {
	var c Cond
	for _, t := range targets {
		tg, err := parseTarget(t)
		if err != nil {
			return c, err
		}
		c.Targets = append(c.Targets, tg)
	}
	for _, t := range excludes {
		tg, err := parseTarget(t)
		if err != nil {
			return c, err
		}
		c.Excludes = append(c.Excludes, tg)
	}
	chain, err := transform.ParseChain(transforms)
	if err != nil {
		return c, err
	}
	c.Chain = chain
	c.ChainID = getChain(chain)
	c.Skip = skip
	c.Negate = negate
	c.OpText = strings.TrimSpace(op + " " + opArg)
	o, err := buildOperator(op, opArg, load)
	if err != nil {
		return c, err
	}
	c.Op = o
	return c, nil
}

// chainCompatible reports whether a chain leaves the value in a form the
// prefilter (urldecode, lower) also produces, so a hint literal is sound.
func chainCompatible(chain []transform.ID) bool {
	hasLower := false
	for _, id := range chain {
		switch id {
		case transform.Lowercase:
			hasLower = true
		case transform.URLDecode, transform.URLDecodeUni, transform.RemoveNulls, transform.CompressWS, transform.Trim, transform.HTMLDecode:
			// these keep or reveal literals, fine
		default:
			return false
		}
	}
	return hasLower
}

func applyDirective(rs *Ruleset, d rulefile.Directive) {
	switch d.Kind {
	case "disable":
		for _, id := range d.IDs {
			if r := rs.byID[id]; r != nil {
				r.disabled = true
			}
		}
	case "override":
		for _, id := range d.IDs {
			r := rs.byID[id]
			if r == nil {
				continue
			}
			for k, v := range d.Override {
				switch k {
				case "paranoia":
					if n, err := atoi(v); err == nil {
						r.Paranoia = uint8(n)
					}
				case "score":
					if n, err := atoi(v); err == nil {
						r.Score = n
					}
				case "mode":
					if m, err := parseMode(v); err == nil {
						r.Mode = m
					}
				case "action":
					if a, err := parseAction(v); err == nil {
						r.Action = a
					}
				}
			}
		}
	case "exclude":
		// file-level exclusions become a rule-attached path/target filter
		for _, id := range d.Exclude.Rules {
			if r := rs.byID[id]; r != nil {
				r.staticExcl = append(r.staticExcl, buildExclusion(d.Exclude.Path, d.Exclude.Methods, d.Exclude.Targets))
			}
		}
	}
}

func buildPrefilter(rules []*Rule) *prefilter {
	pf := &prefilter{}
	var pats [][]byte
	for _, r := range rules {
		if len(r.Hints) == 0 {
			pf.always = append(pf.always, r.ordinal)
			continue
		}
		for _, h := range r.Hints {
			pats = append(pats, h)
			pf.hintOf = append(pf.hintOf, r.ordinal)
		}
	}
	if len(pats) > 0 {
		if m, err := ac.Compile(pats, true); err == nil {
			pf.m = m
		} else {
			// unsound to guess, run everything
			pf.m = nil
			pf.always = nil
			for _, r := range rules {
				pf.always = append(pf.always, r.ordinal)
			}
		}
	}
	return pf
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func atoi(s string) (int, error) {
	n := 0
	neg := false
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad int %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}
