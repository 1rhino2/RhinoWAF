// Package rulefile parses the *.rules DSL into an AST. It does no
// compilation and knows nothing about operators or transforms, so it can
// be tested on its own and the engine decides what the fields mean. The
// format is line oriented with brace blocks and # comments; a rule's op
// takes the raw rest of the line so regexes need no escaping.
package rulefile

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Rule is one parsed rule block, fields as written.
type Rule struct {
	ID         int
	Name       string
	Category   string
	Severity   string
	Score      *int
	Paranoia   int
	Phase      string
	Targets    []string
	Excludes   []string
	Transforms []string
	SkipOpaque bool
	Op         string // operator name
	OpArg      string // raw remainder
	Negate     bool
	Action     string
	Mode       string
	Tags       []string
	Conds      []Cond
	Line       int
}

// Cond is an extra condition inside a rule (all must match).
type Cond struct {
	Targets    []string
	Excludes   []string
	Transforms []string
	Op         string
	OpArg      string
	Negate     bool
	SkipOpaque bool
}

// Directive is a runtime tuning line: disable, override, exclude.
type Directive struct {
	Kind     string // "disable" | "override" | "exclude"
	IDs      []int
	Override map[string]string // for override
	Exclude  Exclusion
	Line     int
}

type Exclusion struct {
	Rules   []int
	Path    string
	Methods []string
	Targets []string
}

// File is everything parsed from one source.
type File struct {
	Rules      []Rule
	Directives []Directive
}

// Parse reads the DSL. It returns as much as it could plus the first error,
// so a caller can report the line.
func Parse(r io.Reader, name string) (*File, error) {
	f := &File{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := stripComment(sc.Text())
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		switch {
		case strings.HasPrefix(t, "rule "):
			ru, err := parseRule(t, sc, &ln)
			if err != nil {
				return f, fmt.Errorf("%s:%d: %w", name, ln, err)
			}
			f.Rules = append(f.Rules, ru)
		case strings.HasPrefix(t, "disable "):
			ids, err := parseIDs(strings.TrimPrefix(t, "disable "))
			if err != nil {
				return f, fmt.Errorf("%s:%d: %w", name, ln, err)
			}
			f.Directives = append(f.Directives, Directive{Kind: "disable", IDs: ids, Line: ln})
		case strings.HasPrefix(t, "override "):
			d, err := parseOverride(t, sc, &ln)
			if err != nil {
				return f, fmt.Errorf("%s:%d: %w", name, ln, err)
			}
			f.Directives = append(f.Directives, d)
		case strings.HasPrefix(t, "exclude {"):
			d, err := parseExclude(sc, &ln)
			if err != nil {
				return f, fmt.Errorf("%s:%d: %w", name, ln, err)
			}
			f.Directives = append(f.Directives, d)
		default:
			return f, fmt.Errorf("%s:%d: unexpected %q", name, ln, t)
		}
	}
	return f, sc.Err()
}

func stripComment(s string) string {
	// # starts a comment only at line start or after whitespace, and never
	// inside quotes. that lets a regex op hold a bare # (like #_memberAccess)
	// while still allowing "severity notice  # a note".
	inQ := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQ = !inQ
		case '#':
			if !inQ && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

func parseRule(head string, sc *bufio.Scanner, ln *int) (Rule, error) {
	r := Rule{Paranoia: 1, Line: *ln}
	// rule <id> "<name>" {
	rest := strings.TrimSpace(strings.TrimPrefix(head, "rule "))
	sp := strings.IndexAny(rest, " \t")
	if sp < 0 {
		return r, fmt.Errorf("rule needs an id")
	}
	id, err := strconv.Atoi(rest[:sp])
	if err != nil {
		return r, fmt.Errorf("bad rule id %q", rest[:sp])
	}
	r.ID = id
	rest = strings.TrimSpace(rest[sp:])
	if strings.HasPrefix(rest, `"`) {
		if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
			r.Name = rest[1 : 1+end]
			rest = strings.TrimSpace(rest[end+2:])
		}
	}
	if !strings.HasPrefix(rest, "{") {
		return r, fmt.Errorf("rule needs a { block")
	}
	// body lines until a closing }
	for sc.Scan() {
		*ln++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "" {
			continue
		}
		if line == "}" {
			return r, nil
		}
		if strings.HasPrefix(line, "cond {") {
			c, err := parseCond(line, sc, ln)
			if err != nil {
				return r, err
			}
			r.Conds = append(r.Conds, c)
			continue
		}
		if err := applyField(&r, line); err != nil {
			return r, err
		}
	}
	return r, fmt.Errorf("rule %d not closed", id)
}

func applyField(r *Rule, line string) error {
	key, val := splitKV(line)
	switch key {
	case "category":
		r.Category = val
	case "severity":
		r.Severity = val
	case "score":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("bad score %q", val)
		}
		r.Score = &n
	case "paranoia":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("bad paranoia %q", val)
		}
		r.Paranoia = n
	case "phase":
		r.Phase = val
	case "targets":
		r.Targets = append(r.Targets, splitCSV(val)...)
	case "exclude":
		r.Excludes = append(r.Excludes, splitCSV(val)...)
	case "transforms":
		r.Transforms = splitCSV(val)
	case "skip":
		r.SkipOpaque = strings.Contains(val, "opaque")
	case "op":
		r.Op, r.OpArg, r.Negate = parseOp(val)
	case "action":
		r.Action = val
	case "mode":
		r.Mode = val
	case "tags":
		r.Tags = splitCSV(val)
	case "hint":
		// hints are optional prefilter literals, engine reads OpArg-derived
		// ones anyway; store as a pseudo tag so nothing breaks if present
	default:
		return fmt.Errorf("unknown field %q", key)
	}
	return nil
}

func parseCond(head string, sc *bufio.Scanner, ln *int) (Cond, error) {
	var c Cond
	// one-liner: cond { targets args  op !contains x }
	inner := strings.TrimSpace(strings.TrimPrefix(head, "cond {"))
	if strings.HasSuffix(inner, "}") {
		return parseCondInline(strings.TrimSpace(strings.TrimSuffix(inner, "}")))
	}
	for sc.Scan() {
		*ln++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "" {
			continue
		}
		if line == "}" {
			return c, nil
		}
		k, v := splitKV(line)
		if err := applyCondField(&c, k, v); err != nil {
			return c, err
		}
	}
	return c, fmt.Errorf("cond not closed")
}

// parseCondInline reads a whole cond off one line. op takes the rest, so it
// must come last; the earlier keys are single-token.
func parseCondInline(s string) (Cond, error) {
	var c Cond
	fields := strings.Fields(s)
	for i := 0; i < len(fields); i++ {
		key := fields[i]
		if key == "op" {
			return c, applyCondField(&c, "op", strings.Join(fields[i+1:], " "))
		}
		if i+1 >= len(fields) {
			break
		}
		if err := applyCondField(&c, key, fields[i+1]); err != nil {
			return c, err
		}
		i++
	}
	return c, nil
}

func applyCondField(c *Cond, key, val string) error {
	switch key {
	case "targets":
		c.Targets = splitCSV(val)
	case "exclude":
		c.Excludes = splitCSV(val)
	case "transforms":
		c.Transforms = splitCSV(val)
	case "skip":
		c.SkipOpaque = strings.Contains(val, "opaque")
	case "op":
		c.Op, c.OpArg, c.Negate = parseOp(val)
	default:
		return fmt.Errorf("unknown cond field %q", key)
	}
	return nil
}

func parseOp(val string) (op, arg string, negate bool) {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "!") {
		negate = true
		val = strings.TrimSpace(val[1:])
	}
	sp := strings.IndexAny(val, " \t")
	if sp < 0 {
		return val, "", negate
	}
	return val[:sp], strings.TrimSpace(val[sp+1:]), negate
}

func parseOverride(head string, sc *bufio.Scanner, ln *int) (Directive, error) {
	d := Directive{Kind: "override", Override: map[string]string{}, Line: *ln}
	rest := strings.TrimSpace(strings.TrimPrefix(head, "override "))
	sp := strings.IndexAny(rest, " \t{")
	if sp < 0 {
		return d, fmt.Errorf("override needs an id")
	}
	id, err := strconv.Atoi(strings.TrimSpace(rest[:sp]))
	if err != nil {
		return d, fmt.Errorf("bad override id")
	}
	d.IDs = []int{id}
	body := rest[sp:]
	// single line: override 941100 { paranoia 2 score 3 }
	if i := strings.IndexByte(body, '{'); i >= 0 {
		body = body[i+1:]
		if j := strings.IndexByte(body, '}'); j >= 0 {
			parseOverrideBody(&d, body[:j])
			return d, nil
		}
		parseOverrideBody(&d, body)
	}
	for sc.Scan() {
		*ln++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "}" {
			return d, nil
		}
		if line != "" {
			parseOverrideBody(&d, line)
		}
	}
	return d, nil
}

func parseOverrideBody(d *Directive, s string) {
	fields := strings.Fields(s)
	for i := 0; i+1 < len(fields); i += 2 {
		d.Override[fields[i]] = fields[i+1]
	}
}

func parseExclude(sc *bufio.Scanner, ln *int) (Directive, error) {
	d := Directive{Kind: "exclude", Line: *ln}
	for sc.Scan() {
		*ln++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "" {
			continue
		}
		if line == "}" {
			return d, nil
		}
		key, val := splitKV(line)
		switch key {
		case "rules":
			ids, err := parseIDs(val)
			if err != nil {
				return d, err
			}
			d.Exclude.Rules = ids
		case "path":
			d.Exclude.Path = val
		case "methods":
			d.Exclude.Methods = splitCSV(val)
		case "targets":
			d.Exclude.Targets = splitCSV(val)
		default:
			return d, fmt.Errorf("unknown exclude field %q", key)
		}
	}
	return d, fmt.Errorf("exclude not closed")
}

func splitKV(line string) (key, val string) {
	sp := strings.IndexAny(line, " \t")
	if sp < 0 {
		return line, ""
	}
	return line[:sp], strings.TrimSpace(line[sp+1:])
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseIDs(s string) ([]int, error) {
	var out []int
	for _, p := range splitCSV(s) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("bad id %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}
