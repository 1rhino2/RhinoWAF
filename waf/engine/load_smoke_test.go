package engine

import "testing"

func TestDefaultRulesetLoads(t *testing.T) {
	rs, err := Loader{}.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.rules) < 20 {
		t.Fatalf("only %d rules loaded", len(rs.rules))
	}
	t.Logf("loaded %d rules, hash %s, categories %v", len(rs.rules), rs.hash, rs.counts)
}
