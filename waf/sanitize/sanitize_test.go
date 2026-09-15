package sanitize

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNoSQLQueryKeyBlocked(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	r := httptest.NewRequest("GET", "/?user%5B%24gt%5D=", nil)
	r.Header.Set("User-Agent", ua)
	if !IsMalicious(r) {
		t.Fatal("nosql operator in query key should be blocked")
	}
}

func TestChromeUserAgentNotMalicious(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	r := httptest.NewRequest("GET", "/about", nil)
	r.Header.Set("User-Agent", ua)
	if IsMalicious(r) {
		t.Fatal("real Chrome UA should not be flagged as malicious input")
	}
}

func TestWeaponizedUserAgentStillBlocked(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "<script>alert(1)</script>")
	if !IsMalicious(r) {
		t.Fatal("XSS in User-Agent should still be blocked")
	}
}

func TestSQLiStillBlockedInQuery(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	r := httptest.NewRequest("GET", "/?id=1+union+select+null", nil)
	r.Header.Set("User-Agent", ua)
	if !IsMalicious(r) {
		t.Fatal("union select in query should still be blocked")
	}
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func get(t *testing.T, target string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("User-Agent", chromeUA)
	return r
}

// these are all things a normal site sees every day and used to get a 403
func TestEverydayTrafficNotMalicious(t *testing.T) {
	for _, u := range []string{
		"/index.php",
		"/wp-login.php",
		"/docs/api.py",
		"/files/document.pdf",
		"/update-profile",
		"/search?q=grant+writing+tips",
		"/search?q=price%3E10.5+or+free",
		"/search?q=difference+between+cats+and+dogs",
		"/search?q=free+advice",
		"/search?q=new+age+music",
		"/search?q=hands--on",
		"/search?q=exec+summary",
		"/search?q=zoom+2.0x",
		"/search?q=do+you+like+cats+or+dogs",
		"/search?q=length%28",
		"/track?v=%24%7Butm_source%7D",
		"/img?src=data:image/png;base64,iVBOR",
		"/user/profile:edit",
		"/q?name=foo+%7C+identity",
	} {
		if IsMalicious(get(t, u)) {
			t.Errorf("%s should not be flagged", u)
		}
	}
}

// and the tightening must not have opened these up
func TestAttacksStillBlocked(t *testing.T) {
	for _, u := range []string{
		"/?id=1+or+1.5=1.5",
		"/?id=1+and+1=1--",
		"/?q=hands--on+or+1=1",
		"/?x=exec+xp_cmdshell",
		"/?id=0x53454c454354",
		"/?id=+ADsAZAByAG8AcAAgAHQAYQBiAGwAZQ--",
		"/?e=%24%7BapplicationScope%7D",
		"/?e=%24%7B7*7%7D",
		"/upload/shell.jpg.php",
		"/?f=shell.php%00.jpg",
		"/?x=data:text/html,%3Cscript%3E",
		"/?x=file:///etc/passwd",
		"/?c=document.cookie",
		"/?c=a;+cat+/etc/passwd",
		"/?c=foo+%7C+whoami",
		"/?id=1+between+1+and+2",
	} {
		if !IsMalicious(get(t, u)) {
			t.Errorf("%s should be flagged", u)
		}
	}
}

func TestFormBodySurvivesInspection(t *testing.T) {
	body := "user=bob&msg=hello+world"
	r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", chromeUA)
	if IsMalicious(r) {
		t.Fatal("clean form flagged")
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != body {
		t.Fatalf("body drained by inspection: %q", got)
	}
	if int64(len(got)) != r.ContentLength {
		t.Fatalf("content length %d does not match restored body %d", r.ContentLength, len(got))
	}
}

func TestFormBodyStillInspected(t *testing.T) {
	for _, body := range []string{
		"id=1'+or+'1'='1",
		"filename=shell.php",
		"file=image.jpg.php",
		"expr=%24%7BapplicationScope%7D",
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if !IsMalicious(r) {
			t.Errorf("form body %q should be flagged", body)
		}
	}
}

func TestAllDoesNotRewriteRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/update-profile?b=2&a=drop&sig=x%2Fy%3D", strings.NewReader("user=bob"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer abc0x1f--'x")
	All(r)
	if r.URL.Path != "/update-profile" {
		t.Errorf("path rewritten to %q", r.URL.Path)
	}
	if r.URL.RawQuery != "b=2&a=drop&sig=x%2Fy%3D" {
		t.Errorf("query rewritten to %q", r.URL.RawQuery)
	}
	if r.Header.Get("Authorization") != "Bearer abc0x1f--'x" {
		t.Errorf("header rewritten to %q", r.Header.Get("Authorization"))
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != "user=bob" {
		t.Errorf("body touched: %q", got)
	}
	// control chars do get stripped
	r2 := httptest.NewRequest("GET", "/a%01b?q=x%02y", nil)
	All(r2)
	if r2.URL.Path != "/ab" || r2.URL.RawQuery != "q=xy" {
		t.Errorf("control chars not stripped: %q %q", r2.URL.Path, r2.URL.RawQuery)
	}
}
