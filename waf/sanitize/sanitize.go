package sanitize

import (
	"bytes"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// pre-compiled for performance
var (
	sqlCommentRegex   = regexp.MustCompile(`--|\b(AND|OR)\b.*?\b(=|>|<)\b`)
	semicolonRegex    = regexp.MustCompile(`;`)
	sqlKeywordsRegex  = regexp.MustCompile(`(?i)\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|ALTER|TRUNCATE|EXEC)\b`)
	javascriptRegex   = regexp.MustCompile(`(?i)javascript:`)
	eventHandlerRegex = regexp.MustCompile(`(?i)on\w+\s*=`)
	base64Regex       = regexp.MustCompile(`(?i)base64,?[a-zA-Z0-9+/=]*`)
	hexRegex          = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	htmlTagRegex      = regexp.MustCompile(`(?i)<.*?>`)
	schemeRegex       = regexp.MustCompile(`(?i)(data|vbscript|file):`)

	sqlOrEqualRegex = regexp.MustCompile(`(?i)or\s+\d+=\d+`)
	dropTableRegex  = regexp.MustCompile(`(?i)drop\s+table`)

	// header injection detection
	crlfRegex        = regexp.MustCompile(`[\r\n]`)
	headerSplitRegex = regexp.MustCompile(`[\r\n]\s*[a-zA-Z-]+\s*:`)

	// ValidateHeaders helpers, compiled once instead of per request
	contentLengthRegex = regexp.MustCompile(`^\d+$`)
	headerNameRegex    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z]$`)

	// word-bounded so "alternative" / "executive" / "grants" stop matching
	sqlKeywordWordRegex = regexp.MustCompile(`\b(select|union|insert|update|delete|drop|create|alter|exec|execute|grant|truncate)\b`)
	boolOpRegex         = regexp.MustCompile(`\b(or|and)\b`)
	// "or 1.5=2" style tautologies, not any sentence with a dot and an "or"
	numCompareRegex = regexp.MustCompile(`\b(or|and)\s+[\d.]+\s*(=|<|>|<=|>=|<>|!=)\s*[\d.]+`)
	// between with numeric/quoted operands, "difference between cats and dogs" is fine
	betweenRegex = regexp.MustCompile(`\bbetween\s+['\d]\S*\s+and\s+['\d]`)
	// 0x hex literal on its own, "zoom 2.0x" is not one
	hexLiteralRegex = regexp.MustCompile(`(^|[^a-z0-9.])0x[0-9a-f]{2,}`)
	// exec of a stored proc, "exec summary" is a search term
	execProcRegex = regexp.MustCompile(`\bexec(ute)?\s+(sp_|xp_|master|@)`)
	// shell metachar followed by a real command word
	shellCmdRegex = regexp.MustCompile(`(;|\||&&|\$\(|` + "`" + `)\s*(cat|ls|id|whoami|uname|nc|wget|curl|bash|sh|rm|chmod)(\s|$|;|\||` + "`" + `|\))`)
	// ${...} only when it looks like an expression or a known EL/SSTI object,
	// not a literal ${placeholder} left in a tracking link
	exprTemplateRegex = regexp.MustCompile(`\$\{[^}]*[#(*=.\[][^}]*\}|\$\{\s*(applicationscope|sessionscope|requestscope|pagecontext|param|paramvalues|header|headervalues|cookie|initparam|class|self|config|request|t\()`)
	// UTF-7 run encoding an ASCII char: "+A" then A-H then a 4-multiple base64
	// digit then "A". Case sensitive on purpose, "+advice" is a plus-space.
	utf7Regex = regexp.MustCompile(`\+A[A-H][AEIMQUYcgkosw048]A`)
	// real scientific notation (1e3, 2e+5), "like+cats" is not, and neither
	// is the "3e10" inside a percent-encoded "%3E10"
	sciNotationRegex = regexp.MustCompile(`(^|[^%0-9])[0-9]+\s*e\s*[+-]?\s*[0-9]`)
	// encoded tag opener, a lone %3E is just a ">" in a search box
	encodedTagRegex = regexp.MustCompile(`%3c(%2f)?(script|img|svg|iframe|body|object|embed|a\b|div|style|link|meta|form|input|video|audio|marquee|math|table|details)`)
	// media decoy in front of an executable extension, shell.jpg.php
	decoyExtRegex = regexp.MustCompile(`\.(jpe?g|png|gif|bmp|webp|svg|pdf|txt|zip|mp4|mp3)\.(php[0-9]?|phtml|phar|aspx?|jspx?|exe|sh|cgi|pl|py|rb)\b`)
)

// maxFormSnapshot caps how much of a urlencoded body we buffer for inspection
const maxFormSnapshot = 1 << 20

// All normalizes the request in place before it is proxied. It only strips
// null bytes and control characters from the path and query; the request
// is not html-escaped or keyword-stripped anymore. Doing that rewrote real
// paths like /update-profile into /-profile and mangled tokens in headers,
// and the body was drained by ParseForm so every form POST hit the backend
// empty. IsMalicious is the gate, this is just cleanup.
func All(r *http.Request) {
	if p := stripControl(r.URL.Path); p != r.URL.Path {
		r.URL.Path = p
		r.URL.RawPath = ""
	}

	// only re-encode when something changed, re-encoding reorders params and
	// breaks signed URLs
	if r.URL.RawQuery != "" {
		q := r.URL.Query()
		changed := false
		for k, vals := range q {
			for i, v := range vals {
				if c := stripControl(v); c != v {
					q[k][i] = c
					changed = true
				}
			}
		}
		if changed {
			r.URL.RawQuery = q.Encode()
		}
	}
}

func stripControl(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 }) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}

// Clean aggressively escapes and strips a single value. Kept for the demo
// handlers, not applied to proxied requests.
func Clean(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, s)
	s = html.EscapeString(s)
	s = strings.ReplaceAll(s, "'", "&#39;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "\\", "")
	s = sqlCommentRegex.ReplaceAllString(s, "")
	s = semicolonRegex.ReplaceAllString(s, "")
	s = sqlKeywordsRegex.ReplaceAllString(s, "")
	s = javascriptRegex.ReplaceAllString(s, "")
	s = eventHandlerRegex.ReplaceAllString(s, "")
	s = base64Regex.ReplaceAllString(s, "")
	s = hexRegex.ReplaceAllString(s, "")
	s = htmlTagRegex.ReplaceAllString(s, "")
	s = schemeRegex.ReplaceAllString(s, "")
	return s
}

// IsMalicious checks ALL input vectors for malicious patterns
func IsMalicious(r *http.Request) bool {
	return checkQueryParams(r) || checkPath(r) || checkFormData(r) ||
		checkMultipartForm(r) || checkHeaders(r) || checkCookies(r) ||
		checkFragment(r) || checkBasicAuth(r)
}

func checkQueryParams(r *http.Request) bool {
	// check raw query string first to catch attacks before URL parsing
	if isMaliciousString(r.URL.RawQuery) {
		return true
	}
	// decoded form catches %5B%24gt%5D -> [$gt]
	if decoded, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
		if isMaliciousString(decoded) {
			return true
		}
	}

	for k, vals := range r.URL.Query() {
		if isMaliciousString(k) {
			return true
		}
		for _, v := range vals {
			if isMaliciousString(v) {
				return true
			}
		}
	}
	return false
}

func checkPath(r *http.Request) bool {
	return isMaliciousString(r.URL.Path)
}

func checkFormData(r *http.Request) bool {
	// only urlencoded bodies are inspected; json/multipart go through as-is
	// (multipart is only checked if the backend-side handler parsed it)
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/x-www-form-urlencoded" {
		return false
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return false
	}

	body := snapshotBody(r, maxFormSnapshot)
	if body == nil {
		return false
	}

	// check the raw form the same way the raw query is checked
	if isMaliciousString(string(body)) {
		return true
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return false
	}
	for k, vs := range vals {
		if isMaliciousString(k) {
			return true
		}
		for _, v := range vs {
			if isMaliciousString(v) || hasUploadExtension(strings.ToLower(v)) {
				return true
			}
		}
	}
	return false
}

// snapshotBody reads up to limit bytes of the body and puts an identical
// reader back so the proxy still forwards it. Returns nil when there is no
// body or it is bigger than limit (size limits are enforced elsewhere).
func snapshotBody(r *http.Request, limit int64) []byte {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if r.ContentLength > limit {
		return nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	_ = r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(buf))
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	if int64(len(buf)) > limit {
		return nil
	}
	return buf
}

func checkMultipartForm(r *http.Request) bool {
	if r.MultipartForm == nil {
		return false
	}
	for _, vals := range r.MultipartForm.Value {
		for _, v := range vals {
			if isMaliciousString(v) {
				return true
			}
		}
	}
	for _, files := range r.MultipartForm.File {
		for _, fh := range files {
			if isMaliciousString(fh.Filename) || hasUploadExtension(strings.ToLower(fh.Filename)) {
				return true
			}
		}
	}
	return false
}

func checkHeaders(r *http.Request) bool {
	// skip payload scanners on these - real Chrome UA has "Win64; x64" (two semicolons)
	// and that used to trip the stacked-query heuristic
	skipPayloadScan := map[string]bool{
		"Content-Type": true, "Content-Length": true, "Host": true,
		"Accept": true, "Accept-Encoding": true,
		"Accept-Language": true, "Connection": true,
		"Sec-Ch-Ua": true, "Sec-Ch-Ua-Mobile": true,
		"Sec-Ch-Ua-Platform": true, "Sec-Fetch-Site": true,
		"Sec-Fetch-Mode": true, "Sec-Fetch-Dest": true, "Sec-Fetch-User": true,
	}

	for k, vals := range r.Header {
		for _, v := range vals {
			// check for CRLF injection (literal and encoded)
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				return true
			}
			// URL-encoded CRLF
			if strings.Contains(strings.ToLower(v), "%0d%0a") || strings.Contains(strings.ToLower(v), "%0a") || strings.Contains(strings.ToLower(v), "%0d") {
				return true
			}
			// double-encoded CRLF
			if strings.Contains(strings.ToLower(v), "%250d%250a") || strings.Contains(strings.ToLower(v), "%250d") || strings.Contains(strings.ToLower(v), "%250a") {
				return true
			}

			// check for null bytes
			if strings.Contains(v, "\x00") {
				return true
			}

			// check for header smuggling patterns
			if strings.Contains(strings.ToLower(v), "transfer-encoding") ||
				strings.Contains(strings.ToLower(v), "content-length") {
				return true
			}

			// User-Agent: only obvious weaponized payloads, not full SQLi heuristics
			// (real Chrome has "Win64; x64" which used to trip stacked-query)
			if k == "User-Agent" {
				if isWeaponizedUserAgent(v) {
					return true
				}
				continue
			}

			if !skipPayloadScan[k] {
				if isMaliciousString(v) {
					return true
				}
			}
		}
	}

	// check for authorization bypass headers
	bypassHeaders := []string{
		"X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
	}
	for _, h := range bypassHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}

	// check for localhost/internal IP in X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if strings.Contains(xff, "127.0.0.1") || strings.Contains(xff, "localhost") {
			return true
		}
	}

	return false
}

// shellshock / XSS in UA only - not the full payload scanner
func isWeaponizedUserAgent(ua string) bool {
	s := strings.ToLower(ua)
	if strings.Contains(s, "<script") || strings.Contains(s, "</script") ||
		strings.Contains(s, "javascript:") || strings.Contains(s, "onerror=") {
		return true
	}
	if strings.Contains(s, "() { :; };") {
		return true
	}
	return false
}

func checkCookies(r *http.Request) bool {
	for _, c := range r.Cookies() {
		if isMaliciousString(c.Value) || isMaliciousString(c.Name) {
			return true
		}
	}
	return false
}

func checkFragment(r *http.Request) bool {
	return isMaliciousString(r.URL.Fragment)
}

func checkBasicAuth(r *http.Request) bool {
	if user, pass, ok := r.BasicAuth(); ok {
		return isMaliciousString(user) || isMaliciousString(pass)
	}
	return false
}

func isMaliciousString(s string) bool {
	if utf7Regex.MatchString(s) {
		return true
	}
	s = strings.ToLower(s)
	// CRLF injection check (for forms and any string input)
	if strings.Contains(s, "\r\n") || strings.Contains(s, "\n") || strings.Contains(s, "\r") {
		return true
	}
	// URL-encoded CRLF
	if strings.Contains(s, "%0d%0a") || strings.Contains(s, "%0a") || strings.Contains(s, "%0d") {
		return true
	}
	return hasXSSPatterns(s) || hasSQLInjectionPatterns(s) ||
		hasPathTraversal(s) || hasCommandInjection(s) ||
		hasLDAPInjection(s) || hasNoSQLInjection(s) ||
		hasSSRFPatterns(s) || hasTemplateInjection(s) ||
		hasMaliciousFileExtension(s) || hasOGNLInjection(s)
}

func hasPathTraversal(s string) bool {
	if strings.Contains(s, "../") || strings.Contains(s, "..\\") {
		return true
	}
	if strings.Contains(s, "%2e%2e%2f") || strings.Contains(s, "%2e%2e/") ||
		strings.Contains(s, "..%2f") || strings.Contains(s, "%2e%2e%5c") {
		return true
	}
	if strings.Contains(s, "/etc/passwd") || strings.Contains(s, "/etc/shadow") ||
		strings.Contains(s, "windows\\system32") {
		return true
	}
	return false
}

func hasCommandInjection(s string) bool {
	// shell metachar + command word, "foo | identity" used to trip "| id"
	if shellCmdRegex.MatchString(s) {
		return true
	}

	// command substitution
	if strings.Contains(s, "`cat ") || strings.Contains(s, "$(wget") ||
		strings.Contains(s, "$(curl") || strings.Contains(s, "`id`") ||
		strings.Contains(s, "$(id)") {
		return true
	}

	// shellshock
	if strings.Contains(s, "() { :; };") {
		return true
	}

	return false
}

func hasLDAPInjection(s string) bool {
	if strings.Contains(s, "*)(uid=*") || strings.Contains(s, "*)(cn=*") ||
		strings.Contains(s, "admin)(&") || strings.Contains(s, "*)(|(*") {
		return true
	}
	return false
}

func hasNoSQLInjection(s string) bool {
	// MongoDB operators in JSON
	if strings.Contains(s, "\"$gt\"") || strings.Contains(s, "\"$ne\"") ||
		strings.Contains(s, "\"$where\"") || strings.Contains(s, "{\"$") {
		return true
	}
	// Object notation (curly brace format)
	if strings.Contains(s, "{$gt") || strings.Contains(s, "{$ne") ||
		strings.Contains(s, "{$where") || strings.Contains(s, "{$eq") ||
		strings.Contains(s, "{$regex") || strings.Contains(s, "{$in") ||
		strings.Contains(s, "{$nin") || strings.Contains(s, "{$exists") {
		return true
	}
	// Array / bracket notation (also as query keys like user[$gt])
	ops := []string{"$gt", "$gte", "$lt", "$lte", "$ne", "$eq", "$regex", "$where", "$in", "$nin", "$exists", "$or", "$and"}
	for _, op := range ops {
		if strings.Contains(s, "["+op+"]") || strings.Contains(s, "["+op) {
			return true
		}
	}
	// URL-encoded bracket ops: %5B%24gt%5D etc
	if strings.Contains(s, "%5b%24") || strings.Contains(s, "%5B%24") {
		return true
	}
	if strings.Contains(s, "%22$gt%22") || strings.Contains(s, "%22$ne%22") ||
		strings.Contains(s, "%22%24gt%22") || strings.Contains(s, "%22%24ne%22") {
		return true
	}
	return false
}

func hasSSRFPatterns(s string) bool {
	// localhost/internal IPs
	if strings.Contains(s, "://localhost") || strings.Contains(s, "://127.0.0.1") ||
		strings.Contains(s, "://0.0.0.0") || strings.Contains(s, "http://10.") ||
		strings.Contains(s, "http://192.168.") || strings.Contains(s, "http://172.16.") {
		return true
	}
	// cloud metadata endpoints
	if strings.Contains(s, "169.254.169.254") || strings.Contains(s, "metadata.google") ||
		strings.Contains(s, "metadata.azure") {
		return true
	}
	return false
}

func hasTemplateInjection(s string) bool {
	// SSTI patterns
	if strings.Contains(s, "{{config") || strings.Contains(s, "{{request") ||
		strings.Contains(s, "{{7*7}}") || strings.Contains(s, "${7*7}") {
		return true
	}
	// Ruby/ERB
	if strings.Contains(s, "<%= system(") || strings.Contains(s, "<% system(") {
		return true
	}
	return false
}

// uploadExts are executable server-side extensions we refuse in upload filenames
var uploadExts = []string{
	".php", ".phtml", ".php3", ".php5", ".phar", ".asp", ".aspx", ".jsp", ".jspx",
	".exe", ".sh", ".bat", ".cmd", ".ps1",
	".cgi", ".pl", ".py", ".rb",
}

// hasMaliciousFileExtension catches extension tricks (shell.php.jpg,
// shell.php%00.jpg). A plain /index.php path is not flagged: that is just
// what a PHP backend serves, and blocking it made the WAF unusable in front
// of WordPress or any Django/Rails app.
func hasMaliciousFileExtension(s string) bool {
	if decoyExtRegex.MatchString(s) {
		return true
	}
	for _, ext := range uploadExts {
		// double extension bypass
		if strings.Contains(s, ext+".") {
			return true
		}
		// null byte truncation, literal or encoded
		if strings.Contains(s, ext+"\x00") || strings.Contains(s, ext+"%00") {
			return true
		}
	}
	return false
}

// hasUploadExtension is the strict form, used for multipart upload filenames
func hasUploadExtension(s string) bool {
	for _, ext := range uploadExts {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return hasMaliciousFileExtension(s)
}

func hasOGNLInjection(s string) bool {
	// OGNL injection patterns (Java Object-Graph Navigation Library)
	if strings.Contains(s, "@java.lang") || strings.Contains(s, "@runtime") ||
		strings.Contains(s, "(#_memberaccess") || strings.Contains(s, "ognl.ognlcontext") ||
		strings.Contains(s, "%{#context") || strings.Contains(s, "${#context") {
		return true
	}
	return false
}

//nolint:gocyclo // XSS detection requires comprehensive pattern matching
func hasXSSPatterns(s string) bool {
	// basic script tags
	if strings.Contains(s, "<script") || strings.Contains(s, "</script") {
		return true
	}

	// protocol handlers. "data:" alone hits data:image/png in query params
	// and "file:" hits /profile:edit, so both need the dangerous form
	if strings.Contains(s, "javascript:") || strings.Contains(s, "vbscript:") ||
		strings.Contains(s, "data:text/html") || strings.Contains(s, "data:application/") ||
		strings.Contains(s, "file://") {
		return true
	}

	// event handlers (comprehensive list)
	eventHandlers := []string{
		"onerror=", "onload=", "onmouseover=", "onclick=", "onfocus=",
		"onblur=", "onchange=", "onsubmit=", "onkeydown=", "onkeyup=",
		"onmouseout=", "onmousemove=", "ondblclick=", "oncontextmenu=",
		"oninput=", "onselect=", "onwheel=", "ondrag=", "ondrop=",
		"onanimationend=", "onanimationstart=", "ontransitionend=",
		"onloadstart=", "onpointerover=", "ontoggle=",
	}
	for _, handler := range eventHandlers {
		if strings.Contains(s, handler) {
			return true
		}
	}

	// HTML tags that can execute scripts
	if strings.Contains(s, "<iframe") || strings.Contains(s, "<svg") ||
		strings.Contains(s, "<embed") || strings.Contains(s, "<object") ||
		strings.Contains(s, "<form") || strings.Contains(s, "<link") ||
		strings.Contains(s, "<meta") || strings.Contains(s, "<base") ||
		strings.Contains(s, "<img") || strings.Contains(s, "<video") ||
		strings.Contains(s, "<audio") || strings.Contains(s, "<body") ||
		strings.Contains(s, "<input") || strings.Contains(s, "<details") ||
		strings.Contains(s, "<template") || strings.Contains(s, "<slot") {
		return true
	}

	// CSS injection
	if strings.Contains(s, "expression(") || strings.Contains(s, "@import") ||
		strings.Contains(s, "behavior:") || strings.Contains(s, "url(") {
		return true
	}

	// DOM-based and special patterns. "document." on its own matched
	// /files/document.pdf, so only the sinks
	if strings.Contains(s, "document.cookie") || strings.Contains(s, "document.write") ||
		strings.Contains(s, "document.location") || strings.Contains(s, "document.domain") ||
		strings.Contains(s, "window.location") || strings.Contains(s, "window.open") ||
		strings.Contains(s, "window.name") ||
		strings.Contains(s, "eval(") || strings.Contains(s, "alert(") ||
		strings.Contains(s, "prompt(") || strings.Contains(s, "confirm(") {
		return true
	}

	// XML/XHTML vectors
	if strings.Contains(s, "<![cdata[") || strings.Contains(s, "<!entity") ||
		strings.Contains(s, "xmlns") {
		return true
	}

	// Template injection. ${name} placeholders are common in urls, only
	// flag when the braces hold an expression
	if strings.Contains(s, "{{constructor") || strings.Contains(s, "dangerouslysetinnerhtml") ||
		strings.Contains(s, "v-html") || exprTemplateRegex.MatchString(s) {
		return true
	}

	// Encoding bypasses. %3C/%3E on their own are just < and > in a
	// search term, the decoded pass catches the actual tag
	if strings.Contains(s, "&#") || strings.Contains(s, "\\u") ||
		strings.Contains(s, "\\x") || encodedTagRegex.MatchString(s) {
		return true
	}

	return false
}

//nolint:gocyclo // SQL injection detection requires extensive pattern checking
func hasSQLInjectionPatterns(s string) bool {
	if strings.Contains(s, "union select") || strings.Contains(s, "union all select") {
		return true
	}
	if strings.Contains(s, "drop table") || strings.Contains(s, "drop database") {
		return true
	}
	if strings.Contains(s, "' or '1'='1") || strings.Contains(s, "' or 1=1") ||
		strings.Contains(s, "\" or \"1\"=\"1") || strings.Contains(s, "or 1=1--") {
		return true
	}
	if strings.Contains(s, "'; exec") || strings.Contains(s, "'; drop") {
		return true
	}
	if strings.Contains(s, "waitfor delay") {
		return true
	}
	if strings.Contains(s, "' order by") && strings.Contains(s, "--") {
		return true
	}
	if strings.Contains(s, "admin'--") || strings.Contains(s, "admin' --") {
		return true
	}
	if (strings.Contains(s, "' and ") || strings.Contains(s, "' or ")) &&
		(strings.Contains(s, "'='") || strings.Contains(s, "=")) {
		return true
	}

	// stacked queries - improved detection
	if strings.Contains(s, "; delete") || strings.Contains(s, "; drop") ||
		strings.Contains(s, "; update") || strings.Contains(s, "; insert") ||
		strings.Contains(s, ";delete") || strings.Contains(s, ";drop") ||
		strings.Contains(s, ";update") || strings.Contains(s, ";insert") {
		return true
	}

	// stacked queries: need statement-ish shape, not UA junk like "Win64; x64"
	if strings.Count(s, ";") >= 2 && containsSQLKeyword(s) {
		return true
	}

	// comment variations - improved
	if (strings.Contains(s, "/*") && strings.Contains(s, "*/")) ||
		strings.Contains(s, "/**/") {
		return true
	}
	// "hands--on" contains "and", so the or/and has to be a word
	if strings.Contains(s, "--") || strings.HasSuffix(s, "#") {
		if containsSQLKeyword(s) || boolOpRegex.MatchString(s) {
			return true
		}
	}

	// encoding bypasses
	if strings.Contains(s, "\\u") || hexLiteralRegex.MatchString(s) ||
		strings.Contains(s, "char(") || strings.Contains(s, "chr(") {
		return true
	}

	// time-based blind
	if strings.Contains(s, "sleep(") || strings.Contains(s, "benchmark(") ||
		strings.Contains(s, "pg_sleep") || strings.Contains(s, "waitfor") {
		return true
	}

	// advanced functions - improved
	if strings.Contains(s, "exec(") || strings.Contains(s, "execute(") ||
		execProcRegex.MatchString(s) ||
		strings.Contains(s, "xp_cmdshell") || strings.Contains(s, "sp_executesql") ||
		strings.Contains(s, "into outfile") || strings.Contains(s, "into dumpfile") ||
		strings.Contains(s, "load_file") || strings.Contains(s, "load data") {
		return true
	}

	// privilege escalation. "grant " alone blocked "grant writing tips"
	if strings.Contains(s, "grant all") || strings.Contains(s, "grant select") ||
		strings.Contains(s, "grant insert") || strings.Contains(s, "grant update") ||
		strings.Contains(s, "grant delete") || strings.Contains(s, "grant execute") ||
		strings.Contains(s, "create user") || strings.Contains(s, "alter user") ||
		strings.Contains(s, "revoke all") || strings.Contains(s, "identified by") {
		return true
	}

	// nosql injection - check for MongoDB operators
	if strings.Contains(s, "[$ne]") || strings.Contains(s, "[$gt]") ||
		strings.Contains(s, "[$lt]") || strings.Contains(s, "[$regex]") ||
		strings.Contains(s, "[$where]") || strings.Contains(s, "[$in]") {
		return true
	}

	// boolean blind variations, the functions need sql context around them
	if strings.Contains(s, "or true") || strings.Contains(s, "and false") {
		return true
	}
	if strings.Contains(s, "ascii(") || strings.Contains(s, "substring(") ||
		strings.Contains(s, "length(") {
		if containsSQLKeyword(s) || strings.Contains(s, "'") || boolOpRegex.MatchString(s) {
			return true
		}
	}

	// error-based
	if strings.Contains(s, "updatexml") || strings.Contains(s, "extractvalue") ||
		strings.Contains(s, "convert(") {
		return true
	}

	// order/group by - only flag if combined with dangerous patterns
	if strings.Contains(s, "order by") || strings.Contains(s, "group by") {
		if containsSQLKeyword(s) || strings.Contains(s, "--") || strings.Contains(s, "#") {
			return true
		}
	}

	// database fingerprinting
	if strings.Contains(s, "version()") || strings.Contains(s, "@@version") ||
		strings.Contains(s, "database()") || strings.Contains(s, "user()") {
		return true
	}

	// out-of-band exfil
	if strings.Contains(s, "load_file") || strings.Contains(s, "utl_http") ||
		strings.Contains(s, "dbms_pipe") || strings.Contains(s, "master..") ||
		strings.Contains(s, "openrowset") {
		return true
	}

	// batch queries - semicolon with SQL keywords
	if strings.Contains(s, ";") && containsSQLKeyword(s) {
		return true
	}

	// evasion: tab/newline mixing
	if strings.Contains(s, "\t") || strings.Contains(s, "\n") || strings.Contains(s, "\r") {
		if containsSQLKeyword(s) || strings.Contains(s, " or ") || strings.Contains(s, " and ") {
			return true
		}
	}

	// evasion: parenthesis obfuscation - (1)or(1)=(1) pattern
	if strings.Count(s, "(") > 2 || strings.Count(s, ")") > 2 {
		if containsSQLKeyword(s) || strings.Contains(s, ")or(") || strings.Contains(s, ")and(") {
			return true
		}
	}

	// evasion: bitwise operators with or/and
	if (strings.Contains(s, "^") || strings.Contains(s, "&")) &&
		(strings.Contains(s, " or ") || strings.Contains(s, " and ") ||
			strings.Contains(s, "+or+") || strings.Contains(s, "+and+")) {
		return true
	}

	// evasion: string concatenation with quotes - '1'='1' pattern
	if strings.Count(s, "'+'") >= 1 || strings.Contains(s, "+'") {
		if strings.Contains(s, " or ") || strings.Contains(s, " and ") ||
			strings.Contains(s, "'or'") || strings.Contains(s, "'and'") ||
			containsSQLKeyword(s) {
			return true
		}
	}

	// evasion: LIKE with and/or, needs a quote or wildcard so
	// "do you like cats or dogs" passes
	if strings.Contains(s, " like ") || strings.Contains(s, " like'") ||
		strings.Contains(s, "'like'") {
		if (strings.Contains(s, "'") || strings.Contains(s, "%")) &&
			(strings.Contains(s, " or ") || strings.Contains(s, " and ") ||
				strings.Contains(s, "+or+") || strings.Contains(s, "+and+")) {
			return true
		}
	}

	// charset: UTF-16 bypass - %00 with SQL patterns
	if strings.Contains(s, "%00") {
		if strings.Contains(s, " or ") || strings.Contains(s, " and ") ||
			containsSQLKeyword(s) || strings.Contains(s, "%00o%00r%00") {
			return true
		}
	}

	// charset: Unicode encoding - %u format (very broad detection)
	if strings.Contains(s, "%u") {
		return true
	}

	// logic: XOR tautology - includes patterns like '1'='1'
	if strings.Contains(s, " xor ") || strings.Contains(s, "+xor+") {
		if strings.Contains(s, "true") || strings.Contains(s, "1=1") ||
			strings.Contains(s, "'1'='1'") || strings.Contains(s, "'='") {
			return true
		}
	}

	// logic: BETWEEN with numeric or quoted operands
	if betweenRegex.MatchString(strings.ReplaceAll(s, "+", " ")) {
		return true
	}

	// type-juggling: "or 1.5=1.5" tautology. Used to be any dot plus any
	// comparator plus any or/and, which blocked "price>10.5 or free"
	if numCompareRegex.MatchString(strings.ReplaceAll(s, "+", " ")) {
		return true
	}

	// type-juggling: scientific notation next to sql context. The old
	// "e+" substring matched every "like+cats" plus-encoded query
	if sciNotationRegex.MatchString(s) &&
		(containsSQLKeyword(s) || strings.Contains(s, " or ") || strings.Contains(s, " and ") ||
			strings.Contains(s, "+or+") || strings.Contains(s, "+and+")) {
		return true
	}

	// race: LOCK TABLES (plural)
	if strings.Contains(s, "lock table") || strings.Contains(s, "lock+table") ||
		strings.Contains(s, "lock tables") || strings.Contains(s, "lock+tables") {
		return true
	}

	// semicolon with quote - '; pattern
	if strings.Contains(s, "';") {
		return true
	}

	// double encoding
	if strings.Contains(s, "%2527") || strings.Contains(s, "%252f") ||
		strings.Contains(s, "%2522") {
		return true
	}

	// standalone dangerous patterns
	if s == "1'--" || s == "1'#" || s == "1';" || strings.HasSuffix(s, "'--") {
		return true
	}

	return sqlOrEqualRegex.MatchString(s) || dropTableRegex.MatchString(s)
}

func containsSQLKeyword(s string) bool {
	return sqlKeywordWordRegex.MatchString(s)
}

// ValidateHeaders checks for malformed or malicious headers
// Returns true if headers are valid, false otherwise
func ValidateHeaders(r *http.Request) (bool, string) {
	// Check for excessively long header values (potential buffer overflow)
	const maxHeaderLength = 8192

	for name, values := range r.Header {
		// Validate header name
		if !isValidHeaderName(name) {
			return false, "invalid header name: " + name
		}

		for _, value := range values {
			// Check for null bytes
			if strings.Contains(value, "\x00") {
				return false, "null byte in header value: " + name
			}

			// Check for CRLF injection (header splitting)
			if crlfRegex.MatchString(value) {
				return false, "CRLF characters in header value: " + name
			}

			// Check for header injection attempts
			if headerSplitRegex.MatchString(value) {
				return false, "header injection attempt detected: " + name
			}

			// Check length
			if len(value) > maxHeaderLength {
				return false, "header value too long: " + name
			}

			// Check for invalid UTF-8
			if !utf8.ValidString(value) {
				return false, "invalid UTF-8 in header: " + name
			}
		}
	}

	// Validate Host header
	host := r.Host
	if host == "" {
		return false, "missing Host header"
	}

	// Check for suspicious characters in Host header
	if strings.ContainsAny(host, "\r\n\x00") {
		return false, "invalid characters in Host header"
	}

	// Validate Content-Length if present
	if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		// Content-Length should only contain digits
		if !contentLengthRegex.MatchString(contentLength) {
			return false, "invalid Content-Length header"
		}
	}

	// Check for duplicate critical headers
	criticalHeaders := []string{"Host", "Content-Length", "Transfer-Encoding"}
	for _, header := range criticalHeaders {
		if len(r.Header[header]) > 1 {
			return false, "duplicate " + header + " header"
		}
	}

	// Detect smuggling attempts (conflicting Content-Length and Transfer-Encoding)
	if r.Header.Get("Content-Length") != "" && r.Header.Get("Transfer-Encoding") != "" {
		return false, "both Content-Length and Transfer-Encoding present (smuggling attempt)"
	}

	return true, ""
}

// isValidHeaderName checks if a header name contains only valid characters
func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}

	// Header names should only contain alphanumeric characters and hyphens
	// and should not start or end with a hyphen
	return headerNameRegex.MatchString(name)
}
