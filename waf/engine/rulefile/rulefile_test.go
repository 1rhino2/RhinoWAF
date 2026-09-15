package rulefile

import (
	"strings"
	"testing"
)

const sample = `
# a comment
rule 942100 "SQL injection" {
    category   sqli
    severity   critical
    paranoia   1
    phase      request-body
    targets    args, cookies, json
    exclude    args[__VIEWSTATE]
    transforms urldecode, lower
    op         sqli
    action     score
    tags       owasp:A03, cwe:89
}

rule 931130 "RFI with IP host" {
    category rfi
    op rx (?:ftps?|https?)://(?:\d{1,3}\.){3}\d{1,3}  # a regex with special chars
    cond { targets args  op !contains example.com }
}

disable 920350
override 941100 { paranoia 2 score 3 }
exclude {
    rules 942100, 942190
    path /api/search*
    methods POST
    targets args[q]
}
`

func TestParse(t *testing.T) {
	f, err := Parse(strings.NewReader(sample), "sample")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 2 {
		t.Fatalf("got %d rules", len(f.Rules))
	}
	r := f.Rules[0]
	if r.ID != 942100 || r.Name != "SQL injection" || r.Category != "sqli" || r.Severity != "critical" {
		t.Fatalf("rule 0: %+v", r)
	}
	if len(r.Targets) != 3 || r.Op != "sqli" || len(r.Tags) != 2 {
		t.Fatalf("rule 0 fields: %+v", r)
	}
	if len(r.Excludes) != 1 || r.Excludes[0] != "args[__VIEWSTATE]" {
		t.Fatalf("exclude: %v", r.Excludes)
	}
	// the regex with # inside must survive
	r2 := f.Rules[1]
	if !strings.Contains(r2.OpArg, `\d{1,3}`) {
		t.Fatalf("regex mangled: %q", r2.OpArg)
	}
	if len(r2.Conds) != 1 || !r2.Conds[0].Negate || r2.Conds[0].Op != "contains" {
		t.Fatalf("cond: %+v", r2.Conds)
	}
	// directives
	var disable, override, exclude bool
	for _, d := range f.Directives {
		switch d.Kind {
		case "disable":
			disable = d.IDs[0] == 920350
		case "override":
			override = d.Override["paranoia"] == "2" && d.Override["score"] == "3"
		case "exclude":
			exclude = len(d.Exclude.Rules) == 2 && d.Exclude.Path == "/api/search*" && len(d.Exclude.Methods) == 1
		}
	}
	if !disable || !override || !exclude {
		t.Fatalf("directives: disable=%v override=%v exclude=%v", disable, override, exclude)
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`rule abc "x" { }`,
		`rule 1 "x" { unknownfield y }`,
		`rule 1 "x" {`,
		`garbage line`,
	}
	for _, b := range bad {
		if _, err := Parse(strings.NewReader(b), "t"); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add(`rule 1 "" { op rx . }`)
	f.Fuzz(func(t *testing.T, s string) { _, _ = Parse(strings.NewReader(s), "f") })
}
