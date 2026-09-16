// Package body pulls apart a request body for inspection without eating it.
// The old sanitize.snapshotBody read a 1 MiB prefix, closed the body and
// re-attached only that prefix, so a chunked upload over the limit reached
// the backend truncated. Snap here re-attaches prefix + the untouched rest,
// so the proxy always forwards the full stream.
package body

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// Limits bound every parser so a hostile body cannot blow up memory or time.
type Limits struct {
	MaxInspect    int64 // bytes of body we buffer and look at
	MaxArgs       int   // args across form/json/query
	MaxArgLen     int   // per value, longer is truncated
	MaxJSONDepth  int
	MaxJSONLeaves int
	MaxParts      int // multipart parts
	MaxFileHead   int // bytes of each upload inspected, 0 = filenames only
}

func (l Limits) argLen() int {
	if l.MaxArgLen <= 0 {
		return 1 << 20
	}
	return l.MaxArgLen
}

// KV is one collected value. Opaque marks JWT/base64 blobs so rules that
// set "skip opaque" leave them alone.
type KV struct {
	Name   string
	Value  string
	Opaque bool
}

// Snapshot is the buffered head plus whether the body was longer than the
// limit (so a rule can flag "too large").
type Snapshot struct {
	Data      []byte
	Truncated bool
}

type replayBody struct {
	r    io.Reader
	orig io.ReadCloser
}

func (b *replayBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *replayBody) Close() error               { return b.orig.Close() }

// Snap buffers up to max bytes and puts the body back intact. It never
// touches ContentLength because it never changes the bytes. GetBody is set
// only when the whole body fit, so a retry replays exactly what we saw.
func Snap(r *http.Request, max int64) Snapshot {
	if r.Body == nil || r.Body == http.NoBody || max <= 0 {
		return Snapshot{}
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		// keep whatever we got, re-attach it so we do not lose the body
		r.Body = io.NopCloser(bytes.NewReader(buf))
		return Snapshot{Data: buf}
	}
	trunc := int64(len(buf)) > max
	if !trunc {
		_ = r.Body.Close()
		data := buf
		r.Body = io.NopCloser(bytes.NewReader(buf))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		return Snapshot{Data: data}
	}
	// over the limit: forward the prefix we read plus the untouched tail
	head := buf[:max]
	r.Body = &replayBody{r: io.MultiReader(bytes.NewReader(buf), r.Body), orig: r.Body}
	return Snapshot{Data: head, Truncated: true}
}

// ParseForm reads a urlencoded body leniently: ';' as a separator, bad
// escapes kept raw. url.ParseQuery bails on both, which let payloads
// through in the old code.
func ParseForm(data []byte, lim Limits, out []KV) []KV {
	for _, pair := range bytes.FieldsFunc(data, func(r rune) bool { return r == '&' || r == ';' }) {
		if len(out) >= lim.MaxArgs && lim.MaxArgs > 0 {
			break
		}
		eq := bytes.IndexByte(pair, '=')
		var k, v []byte
		if eq < 0 {
			k = pair
		} else {
			k, v = pair[:eq], pair[eq+1:]
		}
		out = append(out, KV{Name: unescape(k), Value: clip(unescape(v), lim.argLen())})
	}
	return out
}

func unescape(b []byte) string {
	if s, err := url.QueryUnescape(string(b)); err == nil {
		return s
	}
	// keep the raw form on bad escapes, still replace + with space
	return strings.ReplaceAll(string(b), "+", " ")
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ParseJSON walks every string leaf and key. Names are dotted paths
// ("user.roles.0"), keys are emitted with a ":name" suffix so a rule can
// target json names separately. Bounded by depth and leaf count.
func ParseJSON(data []byte, lim Limits, out []KV) ([]KV, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	w := &jsonWalker{lim: lim, out: out}
	if err := w.walk(dec, "", 0); err != nil {
		return w.out, false
	}
	return w.out, true
}

type jsonWalker struct {
	lim    Limits
	out    []KV
	leaves int
}

func (w *jsonWalker) full() bool {
	return (w.lim.MaxJSONLeaves > 0 && w.leaves >= w.lim.MaxJSONLeaves) ||
		(w.lim.MaxArgs > 0 && len(w.out) >= w.lim.MaxArgs)
}

func (w *jsonWalker) walk(dec *json.Decoder, path string, depth int) error {
	if w.lim.MaxJSONDepth > 0 && depth > w.lim.MaxJSONDepth {
		return errTooDeep
	}
	if w.full() {
		// over the leaf/arg cap: still consume the value, otherwise the
		// caller's dec.More() loop never advances and spins forever. found
		// by the 20000-leaf stress test.
		return skipValue(dec)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := kt.(string)
				w.emit(path+":name", key, true)
				np := key
				if path != "" {
					np = path + "." + key
				}
				if err := w.walk(dec, np, depth+1); err != nil {
					return err
				}
			}
			_, err := dec.Token() // closing }
			return err
		case '[':
			idx := 0
			for dec.More() {
				np := itoa(idx)
				if path != "" {
					np = path + "." + itoa(idx)
				}
				if err := w.walk(dec, np, depth+1); err != nil {
					return err
				}
				idx++
			}
			_, err := dec.Token() // closing ]
			return err
		}
	case string:
		w.emit(path, t, false)
	case json.Number:
		w.emit(path, t.String(), false)
	}
	return nil
}

// skipValue consumes one complete json value without recording it: a
// scalar is one token, an object or array runs to its matching close.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth <= 0 {
			return nil
		}
	}
}

func (w *jsonWalker) emit(name, val string, isName bool) {
	if w.full() || (isName && val == "") {
		return
	}
	w.out = append(w.out, KV{Name: name, Value: clip(val, w.lim.argLen())})
	if !isName {
		w.leaves++
	}
}

var errTooDeep = &tooDeep{}

type tooDeep struct{}

func (*tooDeep) Error() string { return "json too deep" }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

// XMLInfo is what detectxxe reasons about, gathered while extracting text.
type XMLInfo struct {
	HasDoctype        bool
	HasEntityDecl     bool
	HasExternalEntity bool
	HasXInclude       bool
}

// ParseXML pulls text and attribute values out and notes the doctype/entity
// structure that XXE needs. encoding/xml is used non-strictly.
func ParseXML(data []byte, lim Limits, out []KV) ([]KV, XMLInfo) {
	var info XMLInfo
	low := bytes.ToLower(data)
	if bytes.Contains(low, []byte("<!doctype")) {
		info.HasDoctype = true
	}
	if bytes.Contains(low, []byte("<!entity")) {
		info.HasEntityDecl = true
		if bytes.Contains(low, []byte("system")) || bytes.Contains(low, []byte("public")) {
			info.HasExternalEntity = true
		}
	}
	if bytes.Contains(low, []byte(":include")) || bytes.Contains(low, []byte("<xi:")) {
		info.HasXInclude = true
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	for lim.MaxArgs <= 0 || len(out) < lim.MaxArgs {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			for _, a := range t.Attr {
				out = append(out, KV{Name: a.Name.Local, Value: clip(a.Value, lim.argLen())})
			}
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); s != "" {
				out = append(out, KV{Name: "#text", Value: clip(s, lim.argLen())})
			}
		}
	}
	return out, info
}

// FileInfo is one multipart file part.
type FileInfo struct {
	Field    string
	Filename string
	Head     []byte
}

// ParseMultipart parses a fully-buffered multipart body. Values are always
// collected, file heads only when MaxFileHead > 0. A partial body cannot be
// parsed, so callers only pass the snapshot when it was not truncated.
func ParseMultipart(data []byte, contentType string, lim Limits) (fields []KV, files []FileInfo, ok bool) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, nil, false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, nil, false
	}
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	parts := 0
	for lim.MaxParts <= 0 || parts < lim.MaxParts {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		parts++
		if p.FileName() != "" {
			fi := FileInfo{Field: p.FormName(), Filename: p.FileName()}
			if lim.MaxFileHead > 0 {
				fi.Head, _ = io.ReadAll(io.LimitReader(p, int64(lim.MaxFileHead)))
			}
			files = append(files, fi)
		} else {
			v, _ := io.ReadAll(io.LimitReader(p, int64(lim.argLen())))
			fields = append(fields, KV{Name: p.FormName(), Value: string(v)})
		}
		_ = p.Close()
	}
	return fields, files, true
}

// ParseCookies is lenient: r.Cookies() silently drops malformed cookies, so
// we split the header ourselves and keep everything.
func ParseCookies(header string, out []KV) []KV {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		out = append(out, KV{Name: strings.TrimSpace(name), Value: strings.Trim(strings.TrimSpace(val), "\"")})
	}
	return out
}
