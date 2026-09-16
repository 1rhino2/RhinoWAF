package body

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var lim = Limits{MaxInspect: 1 << 20, MaxArgs: 500, MaxArgLen: 65536, MaxJSONDepth: 32, MaxJSONLeaves: 5000, MaxParts: 100}

func TestSnapSmallReattach(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("hello body"))
	snap := Snap(r, 1024)
	if string(snap.Data) != "hello body" || snap.Truncated {
		t.Fatalf("snap: %q %v", snap.Data, snap.Truncated)
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != "hello body" {
		t.Fatalf("backend got %q", got)
	}
	// GetBody replays
	rc, _ := r.GetBody()
	g2, _ := io.ReadAll(rc)
	if string(g2) != "hello body" {
		t.Fatalf("getbody %q", g2)
	}
}

func TestSnapOverLimitForwardsFull(t *testing.T) {
	full := strings.Repeat("A", 100) + strings.Repeat("B", 100)
	r := httptest.NewRequest("POST", "/", strings.NewReader(full))
	r.ContentLength = -1 // simulate chunked
	snap := Snap(r, 100)
	if !snap.Truncated || len(snap.Data) != 100 {
		t.Fatalf("snap head %d trunc %v", len(snap.Data), snap.Truncated)
	}
	// the backend must still receive all 200 bytes, this is the bug we fixed
	got, _ := io.ReadAll(r.Body)
	if string(got) != full {
		t.Fatalf("backend got %d bytes, want %d", len(got), len(full))
	}
}

func TestParseForm(t *testing.T) {
	out := ParseForm([]byte("a=1&b=hello+world&c;d=%27or%271&noval"), lim, nil)
	want := map[string]string{"a": "1", "b": "hello world", "c": "", "d": "'or'1", "noval": ""}
	if len(out) != 5 {
		t.Fatalf("got %d kvs: %+v", len(out), out)
	}
	for _, kv := range out {
		if want[kv.Name] != kv.Value {
			t.Errorf("%s=%q want %q", kv.Name, kv.Value, want[kv.Name])
		}
	}
	// bad escape kept, not dropped
	out = ParseForm([]byte("x=%zz"), lim, nil)
	if out[0].Value != "%zz" {
		t.Errorf("bad escape: %q", out[0].Value)
	}
}

func TestParseJSON(t *testing.T) {
	body := `{"user":{"name":"bob","roles":["admin","x' or 1=1"]},"n":42,"ok":true}`
	out, ok := ParseJSON([]byte(body), lim, nil)
	if !ok {
		t.Fatal("parse failed")
	}
	got := map[string]string{}
	for _, kv := range out {
		got[kv.Name] = kv.Value
	}
	if got["user.name"] != "bob" || got["user.roles.1"] != "x' or 1=1" || got["n"] != "42" {
		t.Fatalf("json walk: %+v", got)
	}
	// keys are emitted as :name
	found := false
	for _, kv := range out {
		if kv.Name == "user:name" && kv.Value == "roles" {
			found = true
		}
	}
	if !found {
		t.Error("json key not emitted")
	}
}

func TestParseJSONDepthBound(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 100) + "1" + strings.Repeat("}", 100)
	_, ok := ParseJSON([]byte(deep), Limits{MaxJSONDepth: 10, MaxArgs: 100, MaxJSONLeaves: 100}, nil)
	if ok {
		t.Fatal("should have hit depth limit")
	}
}

func TestParseXML(t *testing.T) {
	x := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root attr="v">text&xxe;</root>`
	out, info := ParseXML([]byte(x), lim, nil)
	if !info.HasDoctype || !info.HasEntityDecl || !info.HasExternalEntity {
		t.Fatalf("xxe info: %+v", info)
	}
	var sawAttr bool
	for _, kv := range out {
		if kv.Name == "attr" && kv.Value == "v" {
			sawAttr = true
		}
	}
	if !sawAttr {
		t.Errorf("attr not extracted: %+v", out)
	}
}

func TestParseMultipart(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("comment", "hello")
	fw, _ := w.CreateFormFile("upload", "shell.php")
	_, _ = fw.Write([]byte("<?php system($_GET[c]); ?>"))
	w.Close()

	fields, files, ok := ParseMultipart(buf.Bytes(), w.FormDataContentType(), Limits{MaxParts: 10, MaxArgLen: 1000, MaxFileHead: 64})
	if !ok {
		t.Fatal("parse failed")
	}
	if len(fields) != 1 || fields[0].Value != "hello" {
		t.Fatalf("fields: %+v", fields)
	}
	if len(files) != 1 || files[0].Filename != "shell.php" {
		t.Fatalf("files: %+v", files)
	}
	if !strings.Contains(string(files[0].Head), "<?php") {
		t.Errorf("file head not read: %q", files[0].Head)
	}
}

func TestParseCookies(t *testing.T) {
	out := ParseCookies(`session="abc"; theme=dark; broken; x=' or 1=1`, nil)
	got := map[string]string{}
	for _, kv := range out {
		got[kv.Name] = kv.Value
	}
	if got["session"] != "abc" || got["theme"] != "dark" || got["x"] != "' or 1=1" {
		t.Fatalf("cookies: %+v", got)
	}
	if _, ok := got["broken"]; !ok {
		t.Error("valueless cookie dropped")
	}
}

func FuzzParseJSON(f *testing.F) {
	f.Add(`{"a":[1,2,{"b":"c"}]}`)
	f.Add(`{`)
	f.Fuzz(func(t *testing.T, s string) { ParseJSON([]byte(s), lim, nil) })
}

func FuzzParseForm(f *testing.F) {
	f.Add("a=1&b=2")
	f.Fuzz(func(t *testing.T, s string) { ParseForm([]byte(s), lim, nil) })
}

// regression: with more leaves than the cap, the walker used to return
// without consuming the value and the array loop spun forever
func TestParseJSONLeafCapDoesNotHang(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"items":[`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`"v"`)
	}
	sb.WriteString(`],"after":"seen"}`)
	done := make(chan bool, 1)
	var out []KV
	var ok bool
	go func() {
		out, ok = ParseJSON([]byte(sb.String()), Limits{MaxJSONLeaves: 100, MaxArgs: 1000, MaxJSONDepth: 32}, nil)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ParseJSON hung on a body over the leaf cap")
	}
	if !ok {
		t.Fatal("parse reported failure")
	}
	if len(out) > 300 {
		t.Fatalf("leaf cap not honored: %d values", len(out))
	}
}
