package engine

import (
	"bufio"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// External payload lists. Set RHINOWAF_SECLISTS to a seclists checkout
// (default /usr/share/seclists) and this walks the attack lists below through
// the engine as a query param, a form field and a json value, reporting the
// catch rate per file. It only fails when RHINOWAF_SECLISTS_MIN (a percent)
// is set and a file lands under it, so the default run is a report, not a
// gate: these lists mix live payloads with fragments that are not attacks on
// their own, and 100% on them would mean we block prose.
var seclistsAttackFiles = []string{
	"Fuzzing/Databases/SQLi/Generic-SQLi.txt",
	"Fuzzing/Databases/SQLi/quick-SQLi.txt",
	"Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
	"Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",
	"Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
	"Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
	"Fuzzing/Databases/SQLi/NoSQL.txt",
	"Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
	"Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
	"Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",
	"Fuzzing/XSS/human-friendly/XSS-payloadbox.txt",
	"Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
	"Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
	"Fuzzing/LFI/LFI-Jhaddix.txt",
	"Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
	"Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
	"Fuzzing/command-injection-commix.txt",
	"Fuzzing/template-engines-expression.txt",
	"Fuzzing/XXE-Fuzzing.txt",
}

// lists that should mostly NOT block: junk strings that break parsers but
// are not attacks (emoji, rtl, zalgo, long unicode). reported the other way
// round, as a block rate.
var seclistsNoiseFiles = []string{
	"Fuzzing/big-list-of-naughty-strings.txt",
}

func seclistsRoot() string {
	if r := os.Getenv("RHINOWAF_SECLISTS"); r != "" {
		return r
	}
	return "/usr/share/seclists"
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// each payload is tried three ways; a block on any counts as caught, since
// the point is "does the engine see it wherever it lands".
func blockedAnyWhere(e *Engine, p string) bool {
	if inQuery(e, p).Blocked() {
		return true
	}
	if inBody(e, p).Blocked() {
		return true
	}
	body := `{"q":` + jsonQuote(p) + `}`
	r := httptest.NewRequest("POST", "/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return e.Inspect(r).Blocked()
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestSeclistsCorpus(t *testing.T) {
	root := seclistsRoot()
	if _, err := os.Stat(root); err != nil {
		t.Skipf("no seclists at %s", root)
	}
	e := testEngine(t)
	minPct := -1.0
	if v := os.Getenv("RHINOWAF_SECLISTS_MIN"); v != "" {
		_, _ = fmt.Sscanf(v, "%f", &minPct)
	}

	type row struct {
		file          string
		total, caught int
		misses        []string
	}
	var rows []row
	for _, rel := range seclistsAttackFiles {
		lines, err := readLines(filepath.Join(root, rel))
		if err != nil {
			t.Logf("skip %s: %v", rel, err)
			continue
		}
		r := row{file: rel}
		for _, p := range lines {
			r.total++
			if blockedAnyWhere(e, p) {
				r.caught++
			} else if len(r.misses) < 8 {
				r.misses = append(r.misses, p)
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].file < rows[j].file })
	t.Log("attack lists (caught/total):")
	for _, r := range rows {
		pct := 100 * float64(r.caught) / float64(max(r.total, 1))
		t.Logf("  %5.1f%%  %5d/%-5d %s", pct, r.caught, r.total, r.file)
		if minPct >= 0 && pct < minPct {
			t.Errorf("%s under %.0f%%: %.1f%%, sample misses: %q", r.file, minPct, pct, r.misses)
		}
	}
	if os.Getenv("RHINOWAF_SECLISTS_MISSES") != "" {
		for _, r := range rows {
			for _, m := range r.misses {
				t.Logf("  miss %s: %q", filepath.Base(r.file), m)
			}
		}
	}

	t.Log("noise lists (blocked/total, lower is better):")
	for _, rel := range seclistsNoiseFiles {
		lines, err := readLines(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		blocked := 0
		var hits []string
		for _, p := range lines {
			if blockedAnyWhere(e, p) {
				blocked++
				if len(hits) < 500 {
					hits = append(hits, p)
				}
			}
		}
		t.Logf("  %5.1f%%  %5d/%-5d %s", 100*float64(blocked)/float64(max(len(lines), 1)), blocked, len(lines), rel)
		if os.Getenv("RHINOWAF_SECLISTS_MISSES") != "" {
			for _, h := range hits {
				t.Logf("  blocked noise: %q", h)
			}
		}
	}
}
