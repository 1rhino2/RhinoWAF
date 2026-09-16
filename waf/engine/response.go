package engine

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ModifyResponse is the httputil.ReverseProxy hook. It never returns an
// error, since the proxy would turn that into a 502 and hide the backend's
// real answer. Phase 3 looks at status and headers, phase 4 at a bounded
// prefix of the body when the status and content type say it is worth it.
// On a block in block mode the body is swapped for a short 403 page; in
// detect mode (the default) the response goes out untouched and the event
// is logged.
func (e *Engine) ModifyResponse(resp *http.Response) error {
	if e == nil || !e.cfg.Enabled || resp == nil || resp.Request == nil {
		return nil
	}
	rc := e.cfg.Response
	if rc.Mode == "" || rc.Mode == "off" {
		return nil
	}
	if !statusWanted(rc.InspectStatus, resp.StatusCode) {
		return nil
	}

	var bodyPrefix []byte
	if resp.Body != nil && resp.StatusCode != http.StatusSwitchingProtocols && bodyInspectable(resp.Header) {
		max := rc.MaxBytes
		if max <= 0 {
			max = 16384
		}
		buf, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)))
		if err != nil && len(buf) == 0 {
			return nil
		}
		// put the bytes back in front of whatever is left of the stream
		resp.Body = &replayBody{r: io.MultiReader(bytes.NewReader(buf), resp.Body), orig: resp.Body}
		bodyPrefix = buf
		if rc.DecompressGzip && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			if gz, gerr := gzip.NewReader(bytes.NewReader(buf)); gerr == nil {
				// a truncated gzip stream is the normal case here, take what we got
				out, _ := io.ReadAll(io.LimitReader(gz, int64(4*max)))
				_ = gz.Close()
				if len(out) > 0 {
					bodyPrefix = out
				}
			}
		}
	}

	v := e.InspectResponse(resp.Request, resp.StatusCode, resp.Header, bodyPrefix)
	if len(v.Evidence) == 0 {
		return nil
	}
	req := resp.Request
	e.LogEvent(v, req.Header.Get("X-Request-ID"), clientIP(req), req.Host, req.Method, req.URL.Path)

	if !v.Blocked() {
		return nil
	}
	// block: drop the backend's body and send our own
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	page := blockPage(v)
	resp.StatusCode = http.StatusForbidden
	resp.Status = "403 Forbidden"
	resp.Body = io.NopCloser(bytes.NewReader(page))
	resp.ContentLength = int64(len(page))
	h := resp.Header
	for _, k := range []string{"Content-Encoding", "ETag", "Last-Modified", "Content-Range", "Transfer-Encoding", "Content-Disposition"} {
		h.Del(k)
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(page)))
	h.Set("Cache-Control", "no-store")
	return nil
}

type replayBody struct {
	r    io.Reader
	orig io.ReadCloser
}

func (b *replayBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *replayBody) Close() error               { return b.orig.Close() }

// statusWanted: "5xx" (default), "4xx+" or "all"
func statusWanted(mode string, status int) bool {
	switch mode {
	case "all":
		return true
	case "4xx+", "4xx":
		return status >= 400
	default:
		return status >= 500
	}
}

// only text-ish bodies carry a stack trace or an sql error worth reading
func bodyInspectable(h http.Header) bool {
	ct := strings.ToLower(h.Get("Content-Type"))
	if ct == "" {
		return true
	}
	if strings.HasPrefix(ct, "text/event-stream") {
		return false
	}
	for _, ok := range []string{"text/html", "text/plain", "application/json", "application/problem+json", "application/xml", "text/xml", "application/javascript"} {
		if strings.HasPrefix(ct, ok) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return strings.Trim(r.RemoteAddr[:i], "[]")
	}
	return r.RemoteAddr
}

// blockPage is deliberately tiny and self-contained so the engine does not
// need the templates package.
func blockPage(v *Verdict) []byte {
	var b bytes.Buffer
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked</title></head><body style=\"font-family:sans-serif;max-width:600px;margin:60px auto\">")
	b.WriteString("<h1>Response blocked</h1><p>The backend's response was withheld by the RhinoWAF detection engine.</p><p>")
	b.WriteString(htmlEsc(v.Summary()))
	if ids := v.RuleIDs(); ids != "" {
		b.WriteString("<br>Rules: ")
		b.WriteString(ids)
	}
	b.WriteString("</p></body></html>")
	return b.Bytes()
}

func htmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}
