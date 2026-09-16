package engine

import (
	"net/http"
	"strings"

	"rhinowaf/waf/engine/body"
	"rhinowaf/waf/engine/transform"
)

// field is one collected input value with its label and kind.
type field struct {
	kind   TargetKind
	name   string // header/arg/json name, "" for path-like
	label  string // args:q, cookies:session, path, ...
	value  []byte
	opaque bool // jwt/base64 blob, skipped by "skip opaque" rules
	idx    int  // stable index for the transform cache
}

// Tx is one request (or response) being evaluated. Reused via a pool.
type Tx struct {
	fields   []field
	cache    *transform.Cache
	limits   body.Limits
	bodySkip string
	nextIdx  int
	cand     []bool // prefilter candidate bitmap, reused
	pfA, pfB []byte // prefilter scratch, reused
}

func newTx() *Tx {
	return &Tx{cache: transform.NewCache()}
}

func (tx *Tx) reset(lim body.Limits) {
	tx.fields = tx.fields[:0]
	tx.cache.Reset()
	tx.bodySkip = ""
	tx.nextIdx = 0
	tx.limits = lim
}

func (tx *Tx) add(kind TargetKind, name, label string, value []byte, opaque bool) {
	tx.fields = append(tx.fields, field{kind: kind, name: name, label: label, value: value, opaque: opaque, idx: tx.nextIdx})
	tx.nextIdx++
}

func (tx *Tx) addStr(kind TargetKind, name, label, value string, opaque bool) {
	tx.add(kind, name, label, []byte(value), opaque)
}

// collectRequestMeta gathers everything available before the body: path,
// query, headers, cookies, host, method, ua.
func (tx *Tx) collectRequestHead(r *http.Request) {
	tx.addStr(TPath, "", "path", r.URL.Path, false)
	tx.addStr(TRawQuery, "", "raw_query", r.URL.RawQuery, false)
	tx.addStr(THost, "", "host", r.Host, false)
	tx.addStr(TMethod, "", "method", r.Method, false)
	tx.addStr(TUA, "", "ua", r.UserAgent(), false)
	tx.addStr(TReferer, "", "referer", r.Referer(), false)
	tx.addStr(TContentType, "", "content_type", r.Header.Get("Content-Type"), false)

	for k, vals := range r.URL.Query() {
		tx.addStr(TArgsNames, k, "args_names:"+strings.ToLower(k), k, false)
		for _, v := range vals {
			tx.addStr(TArgs, k, "args:"+strings.ToLower(k), v, isOpaque(v))
		}
	}
	for name, vals := range r.Header {
		ln := strings.ToLower(name)
		if ln == "cookie" {
			continue
		}
		tx.addStr(THeaderNames, ln, "header_names:"+ln, name, false)
		for _, v := range vals {
			tx.addStr(THeaders, ln, "headers:"+ln, v, false)
		}
	}
	if ck := r.Header.Get("Cookie"); ck != "" {
		for _, kv := range body.ParseCookies(ck, nil) {
			tx.addStr(TCookieNames, kv.Name, "cookie_names:"+strings.ToLower(kv.Name), kv.Name, false)
			tx.addStr(TCookies, kv.Name, "cookies:"+strings.ToLower(kv.Name), kv.Value, isOpaque(kv.Value))
		}
	}
}

// collectRequestBody buffers and parses the body according to its type.
// Returns false if the body was skipped (too large + block policy handled
// by the caller).
func (tx *Tx) collectRequestBody(r *http.Request, maxInspect int64, overLimit string) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return
	}
	snap := body.Snap(r, maxInspect)
	if len(snap.Data) == 0 {
		return
	}
	if snap.Truncated {
		tx.bodySkip = "truncated"
		if overLimit == "skip" {
			return
		}
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	tx.add(TBody, "", "body", snap.Data, false)
	switch {
	case strings.Contains(ct, "application/json"), strings.Contains(ct, "+json"):
		kvs, ok := body.ParseJSON(snap.Data, tx.limits, nil)
		if !ok && tx.bodySkip == "" {
			tx.bodySkip = "json_parse_error"
		}
		for _, kv := range kvs {
			if strings.HasSuffix(kv.Name, ":name") {
				tx.addStr(TJSONNames, kv.Name, "json_names:"+kv.Value, kv.Value, false)
			} else {
				tx.addStr(TJSON, kv.Name, "json:"+kv.Name, kv.Value, kv.Opaque)
			}
		}
	case strings.Contains(ct, "xml"):
		kvs, _ := body.ParseXML(snap.Data, tx.limits, nil)
		for _, kv := range kvs {
			tx.addStr(TXML, kv.Name, "xml:"+kv.Name, kv.Value, false)
		}
	case strings.Contains(ct, "multipart/form-data"):
		if snap.Truncated {
			tx.bodySkip = "multipart_truncated"
			break
		}
		fields, files, ok := body.ParseMultipart(snap.Data, r.Header.Get("Content-Type"), tx.limits)
		if !ok {
			tx.bodySkip = "multipart_parse_error"
			break
		}
		for _, kv := range fields {
			tx.addStr(TArgs, kv.Name, "args:"+strings.ToLower(kv.Name), kv.Value, false)
			tx.addStr(TArgsNames, kv.Name, "args_names:"+strings.ToLower(kv.Name), kv.Name, false)
		}
		for _, f := range files {
			tx.addStr(TFilesNames, f.Field, "files_names:"+strings.ToLower(f.Field), f.Filename, false)
			if len(f.Head) > 0 {
				tx.add(TFilesContent, f.Field, "files_content:"+strings.ToLower(f.Field), f.Head, false)
			}
		}
	case strings.Contains(ct, "application/x-www-form-urlencoded"), ct == "":
		for _, kv := range body.ParseForm(snap.Data, tx.limits, nil) {
			tx.addStr(TArgs, kv.Name, "args:"+strings.ToLower(kv.Name), kv.Value, isOpaque(kv.Value))
			tx.addStr(TArgsNames, kv.Name, "args_names:"+strings.ToLower(kv.Name), kv.Name, false)
		}
	}
}

// collectResponse gathers status and headers, and body if provided.
func (tx *Tx) collectResponse(status int, header http.Header, bodyData []byte) {
	tx.addStr(TRespStatus, "", "resp_status", itoa(status), false)
	for name, vals := range header {
		ln := strings.ToLower(name)
		for _, v := range vals {
			tx.addStr(TRespHeaders, ln, "resp_headers:"+ln, v, false)
		}
	}
	if len(bodyData) > 0 {
		tx.add(TRespBody, "", "resp_body", bodyData, false)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}

// isOpaque flags JWT and base64 blobs so rules can skip them: they are not
// attack vectors and they wreck the sqli/xss detectors.
func isOpaque(v string) bool {
	if len(v) < 24 {
		return false
	}
	// jwt: three base64url segments split by dots
	if dots := strings.Count(v, "."); dots == 2 {
		ok := true
		for _, seg := range strings.Split(v, ".") {
			if len(seg) < 4 || !transform.Base64Shaped([]byte(seg)) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return transform.Base64Shaped([]byte(v))
}
