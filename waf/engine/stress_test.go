package engine

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hostile-shaped but benign inputs: the engine must stay bounded and must
// not block them just for being big.
func TestStressBigInputsStayBounded(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		name string
		req  func() *httptestRequest
	}{
		{"64KB single arg", func() *httptestRequest {
			return form("data=" + strings.Repeat("a", 64<<10))
		}},
		{"5000 args", func() *httptestRequest {
			var sb strings.Builder
			for i := 0; i < 5000; i++ {
				sb.WriteString("k" + itoa(i) + "=v&")
			}
			return form(sb.String())
		}},
		{"json 200 deep", func() *httptestRequest {
			body := strings.Repeat(`{"a":`, 200) + `"x"` + strings.Repeat("}", 200)
			return jsonReq(body)
		}},
		{"json 20000 leaves", func() *httptestRequest {
			var sb strings.Builder
			sb.WriteString(`{"items":[`)
			for i := 0; i < 20000; i++ {
				if i > 0 {
					sb.WriteByte(',')
				}
				sb.WriteString(`"v` + itoa(i) + `"`)
			}
			sb.WriteString(`]}`)
			return jsonReq(sb.String())
		}},
		{"8KB header value", func() *httptestRequest {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("X-Big", strings.Repeat("x", 8<<10))
			return &httptestRequest{r}
		}},
		{"1MB body over inspect limit, chunked", func() *httptestRequest {
			r := httptest.NewRequest("POST", "/upload", bytes.NewReader(bytes.Repeat([]byte("z"), 1<<20)))
			r.ContentLength = -1
			r.Header.Set("Content-Type", "application/octet-stream")
			return &httptestRequest{r}
		}},
		{"null bytes everywhere", func() *httptestRequest {
			return form("a=" + strings.Repeat("\x00", 2000) + "&b=" + strings.Repeat("%00", 2000))
		}},
		{"2000 percent signs", func() *httptestRequest {
			return form("a=" + strings.Repeat("%", 2000))
		}},
		{"unicode soup", func() *httptestRequest {
			return form("a=" + strings.Repeat("\xf0\x9f\x98\x80\xe6\x97\xa5\xd7\xa9\xc3\xa9", 2000))
		}},
		{"many cookies", func() *httptestRequest {
			r := httptest.NewRequest("GET", "/", nil)
			var sb strings.Builder
			for i := 0; i < 300; i++ {
				sb.WriteString("c" + itoa(i) + "=" + strings.Repeat("v", 50) + "; ")
			}
			r.Header.Set("Cookie", sb.String())
			return &httptestRequest{r}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.req().r
			start := time.Now()
			v := e.Inspect(r)
			dur := time.Since(start)
			// generous so the race detector passes too; a hang is what we
			// are after, not a benchmark
			if dur > time.Second {
				t.Errorf("took %s, too slow", dur)
			}
			if v.Blocked() {
				t.Errorf("benign big input blocked: %s [%s]", v.Summary(), v.RuleIDs())
			}
			// whatever we buffered, the backend must still get the whole body
			if r.Body != nil {
				n, _ := io.Copy(io.Discard, r.Body)
				if c.name == "1MB body over inspect limit, chunked" && n != 1<<20 {
					t.Errorf("backend got %d of %d body bytes", n, 1<<20)
				}
			}
		})
	}
}

// an attack buried past the inspect limit of a huge body is out of scope by
// design (inspect_prefix), but one inside the prefix must still be caught
// even when the body is huge.
func TestStressAttackInsideHugeBody(t *testing.T) {
	e := testEngine(t)
	body := "comment=" + urlEnc("<script>alert(1)</script>") + "&pad=" + strings.Repeat("p", 900<<10)
	r := httptest.NewRequest("POST", "/c", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v := e.Inspect(r); !v.Blocked() {
		t.Fatalf("attack in prefix of a 900KB body not blocked (skip=%s)", v.BodySkip)
	}
}

// pool reuse: a huge request must not leave state that changes the next
// verdict, and the arena must not be retained
func TestStressPoolIsolation(t *testing.T) {
	e := testEngine(t)
	for i := 0; i < 50; i++ {
		big := form("data=" + strings.Repeat("a", 200<<10)).r
		e.Inspect(big)
		clean := httptest.NewRequest("GET", "/?q=hello", nil)
		if e.Inspect(clean).Blocked() {
			t.Fatal("clean request blocked after a huge one")
		}
		attack := httptest.NewRequest("GET", "/?q="+urlEnc("' or 1=1--"), nil)
		if !e.Inspect(attack).Blocked() {
			t.Fatal("attack missed after a huge request")
		}
	}
}

type httptestRequest struct{ r *http.Request }

func form(body string) *httptestRequest {
	r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return &httptestRequest{r}
}

func jsonReq(body string) *httptestRequest {
	r := httptest.NewRequest("POST", "/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return &httptestRequest{r}
}
