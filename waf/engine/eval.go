package engine

import (
	"strings"

	"rhinowaf/waf/engine/transform"
)

const maxTransformOut = 262144

// evaluate runs one phase's rules against the collected fields and returns
// the accumulated score, evidence and any forced action.
func (rs *Ruleset) evaluate(tx *Tx, pol *policy, phase Phase) *scorer {
	sc := newScorer(pol.scoringSum)
	rules := rs.byPhase[phase]
	if len(rules) == 0 {
		return sc
	}
	cand := rs.candidates(tx, phase)
	for _, r := range rules {
		if !cand[r.ordinal] {
			continue
		}
		if r.disabled || pol.disabled[r.ID] {
			continue
		}
		if r.Paranoia > pol.paranoia {
			continue
		}
		label, ev, ok := rs.matchRule(tx, pol, r)
		if !ok {
			continue
		}
		// mode: a detect rule (or detect policy) records but never blocks
		effMode := r.Mode
		if pol.mode == ModeDetect || pol.detect[r.ID] {
			effMode = ModeDetect
		}
		if effMode == ModeDetect {
			ev.Mode = "detect"
			if r.Action == ActBlock || r.Action == ActChallenge {
				// downgrade to a score contribution so detect never blocks
				logRule := *r
				logRule.Action = ActLog
				sc.add(&logRule, label, ev)
				continue
			}
		}
		sc.add(r, label, ev)
		if sc.forceAllow {
			return sc
		}
	}
	return sc
}

var prefilterView = []transform.ID{transform.URLDecode, transform.Lowercase}

// candidates marks the rule ordinals worth running, using the prefilter.
// Rules with no usable hint are always in. The bitmap lives on the tx and
// is reused across phases, so this allocates nothing on a warm tx.
func (rs *Ruleset) candidates(tx *Tx, phase Phase) []bool {
	out := tx.cand
	if cap(out) < len(rs.rules) {
		out = make([]bool, len(rs.rules))
	} else {
		out = out[:len(rs.rules)]
		for i := range out {
			out[i] = false
		}
	}
	tx.cand = out
	pf := rs.prefilter[phase]
	if pf == nil {
		for _, r := range rs.byPhase[phase] {
			out[r.ordinal] = true
		}
		return out
	}
	for _, ord := range pf.always {
		out[ord] = true
	}
	if pf.m == nil {
		return out
	}
	// one prefilter view per field: urldecode + lower
	resp := phase == PhaseRespHeaders || phase == PhaseRespBody
	for _, f := range tx.fields {
		if f.kind.isResponse() != resp {
			continue
		}
		var v []byte
		v, tx.pfA, tx.pfB = transform.Run(prefilterView, f.value, tx.pfA, tx.pfB)
		pf.m.Each(v, func(patIdx, _ int) bool {
			out[pf.hintOf[patIdx]] = true
			return true
		})
	}
	return out
}

// matchRule checks every cond; all must match. The primary cond decides the
// label and evidence.
func (rs *Ruleset) matchRule(tx *Tx, pol *policy, r *Rule) (string, Evidence, bool) {
	var primaryLabel string
	var ev Evidence
	for ci := range r.Conds {
		c := &r.Conds[ci]
		label, e, ok := rs.matchCond(tx, r, c)
		if ok == c.Negate {
			return "", Evidence{}, false
		}
		if ci == 0 {
			primaryLabel, ev = label, e
		}
	}
	// exclusions: static (from rule) and policy (from site/path)
	if suppressed(r.staticExcl, tx, primaryLabel) || suppressed(pol.exclusions, tx, primaryLabel) {
		return "", Evidence{}, false
	}
	return primaryLabel, ev, true
}

func suppressed(excls []exclusion, tx *Tx, label string) bool {
	if len(excls) == 0 {
		return false
	}
	for _, e := range excls {
		if e.matchesPath(tx.path(), tx.method()) && e.suppresses(label) {
			return true
		}
	}
	return false
}

// matchCond runs the cond's operator over every field its targets select,
// after the cond's transform chain. First hit wins.
func (rs *Ruleset) matchCond(tx *Tx, r *Rule, c *Cond) (string, Evidence, bool) {
	for i := range tx.fields {
		f := &tx.fields[i]
		if !condSelects(c, f) {
			continue
		}
		if c.Skip && f.opaque {
			continue
		}
		v := tx.cache.Get(f.idx, c.ChainID, c.Chain, f.value, maxTransformOut)
		start, end, ok := c.Op.Match(v)
		if !ok {
			continue
		}
		return f.label, buildEvidence(r, c, f, v, start, end), true
	}
	return "", Evidence{}, false
}

func condSelects(c *Cond, f *field) bool {
	sel := false
	for _, t := range c.Targets {
		if t.Kind == f.kind && t.matchesName(f.name) {
			sel = true
			break
		}
	}
	if !sel {
		return false
	}
	for _, ex := range c.Excludes {
		if ex.Kind == f.kind && ex.matchesName(f.name) {
			return false
		}
	}
	return true
}

func buildEvidence(r *Rule, c *Cond, f *field, v []byte, start, end int) Evidence {
	return Evidence{
		RuleID:     r.ID,
		Name:       r.Name,
		Category:   r.Category,
		Severity:   r.Severity.String(),
		Score:      r.Score,
		Target:     f.label,
		Op:         clipStr(c.OpText, 80),
		Match:      escapeSnippet(v, start, end, 64),
		Window:     window(v, start, end, 24),
		Transforms: chainNames(c.Chain),
		Tags:       r.Tags,
	}
}

func (tx *Tx) path() string {
	for i := range tx.fields {
		if tx.fields[i].kind == TPath {
			return string(tx.fields[i].value)
		}
	}
	return "/"
}

func (tx *Tx) method() string {
	for i := range tx.fields {
		if tx.fields[i].kind == TMethod {
			return string(tx.fields[i].value)
		}
	}
	return "GET"
}

func chainNames(chain []transform.ID) string {
	if len(chain) == 0 {
		return ""
	}
	parts := make([]string, len(chain))
	for i, id := range chain {
		parts[i] = id.String()
	}
	return strings.Join(parts, ",")
}

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func escapeSnippet(v []byte, start, end, max int) string {
	if start < 0 || start > len(v) {
		start = 0
	}
	if end > len(v) {
		end = len(v)
	}
	if end < start {
		end = start
	}
	seg := v[start:end]
	if len(seg) > max {
		seg = seg[:max]
	}
	return escapeBytes(seg)
}

func window(v []byte, start, end, pad int) string {
	if start < 0 {
		start = 0
	}
	if end > len(v) {
		end = len(v)
	}
	lo := start - pad
	if lo < 0 {
		lo = 0
	}
	hi := end + pad
	if hi > len(v) {
		hi = len(v)
	}
	if lo == 0 && hi == len(v) {
		return ""
	}
	return escapeBytes(v[lo:hi])
}

func escapeBytes(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			const hexd = "0123456789abcdef"
			sb.WriteString("\\x")
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&0xf])
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}
