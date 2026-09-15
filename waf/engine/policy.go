package engine

import (
	"path"
	"strings"
)

// exclusion suppresses a rule for certain paths, methods and targets. It is
// how CRS-style runtime tuning works: keep the rule, carve out the one
// endpoint or parameter that legitimately trips it.
type exclusion struct {
	pathGlob string
	prefix   bool
	methods  map[string]bool
	targets  []Target // if set, only these targets are excluded, not the whole rule
}

// buildExclusion turns config/dsl exclusion fields into the runtime form.
func buildExclusion(pathGlob string, methods, targets []string) exclusion {
	e := exclusion{}
	if pathGlob != "" {
		if strings.HasSuffix(pathGlob, "*") && !strings.ContainsAny(pathGlob[:len(pathGlob)-1], "*?[") {
			e.pathGlob = strings.TrimSuffix(pathGlob, "*")
			e.prefix = true
		} else {
			e.pathGlob = pathGlob
		}
	}
	if len(methods) > 0 {
		e.methods = map[string]bool{}
		for _, m := range methods {
			e.methods[strings.ToUpper(strings.TrimSpace(m))] = true
		}
	}
	for _, t := range targets {
		if tg, err := parseTarget(t); err == nil {
			e.targets = append(e.targets, tg)
		}
	}
	return e
}

// matchesPath reports whether the exclusion applies to this request path.
func (e exclusion) matchesPath(p, method string) bool {
	if len(e.methods) > 0 && !e.methods[strings.ToUpper(method)] {
		return false
	}
	if e.pathGlob == "" {
		return true
	}
	if e.prefix {
		return strings.HasPrefix(p, e.pathGlob)
	}
	ok, _ := path.Match(e.pathGlob, p)
	return ok
}

// suppresses reports whether this exclusion silences the given target label.
// An exclusion with no targets silences the whole rule.
func (e exclusion) suppresses(label string) bool {
	if len(e.targets) == 0 {
		return true
	}
	for _, t := range e.targets {
		// label is like "args:q"; build the target's label form to compare
		tl := t.Kind.String()
		if t.Name != "" {
			tl += ":" + t.Name
		}
		if t.Name != "" && strings.HasSuffix(t.Name, "*") {
			base := t.Kind.String() + ":" + strings.TrimSuffix(t.Name, "*")
			if strings.HasPrefix(label, base) {
				return true
			}
		} else if strings.EqualFold(label, tl) || strings.EqualFold(t.Kind.String(), label) {
			return true
		}
	}
	return false
}

// policy is the resolved rule set for one request: the effective mode,
// paranoia ceiling, threshold, and which rules are off or forced to detect.
type policy struct {
	mode          Mode
	paranoia      uint8
	threshold     int
	respThreshold int
	scoringSum    bool
	disabled      map[int]bool
	detect        map[int]bool
	exclusions    []exclusion
}
