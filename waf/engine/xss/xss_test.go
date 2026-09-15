package xss

import "testing"

var positives = []string{
	"<script>alert(1)</script>",
	"<ScRiPt>alert(1)</ScRiPt>",
	"<script src=//evil.com/x.js>",
	"<script/src=//x>",
	"<img src=x onerror=alert(1)>",
	"<img src=x onerror=\"alert(1)\">",
	"<svg onload=alert(1)>",
	"<svg/onload=alert(1)>",
	"<svg><script>alert(1)</script>",
	"<iframe src=javascript:alert(1)>",
	"<iframe src='javascript:alert(1)'>",
	"<body onload=alert(1)>",
	"<details open ontoggle=alert(1)>",
	"<marquee onstart=alert(1)>",
	"<a href=\"javascript:alert(1)\">x</a>",
	"<a href=\"jav&#x09;ascript:alert(1)\">x</a>",
	"<a href=\"jav\tascript:alert(1)\">x</a>",
	"<a href=\"&#106;avascript:alert(1)\">x</a>",
	"<a href = javascript:alert(1) >x</a>",
	"<img src=\"x\" onerror=\"&#97;lert(1)\">",
	"<object data=\"data:text/html;base64,PHNjcmlwdD4=\">",
	"<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
	"<base href=\"javascript:\">",
	"<link rel=stylesheet href=javascript:alert(1)>",
	"<div style=\"width:expression(alert(1))\">",
	"<div style=\"background:url(javascript:alert(1))\">",
	"<style>@import 'javascript:alert(1)'</style>",
	"<svg><animate onbegin=alert(1)>",
	"<math><maction xlink:href=\"javascript:alert(1)\">",
	"<form action=javascript:alert(1)>",
	"<button formaction=javascript:alert(1)>",
	"<input onfocus=alert(1) autofocus>",
	"<video><source onerror=alert(1)>",
	"<embed src=//evil.com>",
	"<image src=x onerror=alert(1)>",
	"+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
	"<img\x00src=x\x00onerror=alert(1)>",
	"<img src=x on\x00error=alert(1)>",
	"<iframe srcdoc=\"<script>alert(1)</script>\">",
	"<a href=\"vbscript:msgbox(1)\">",
	"{{constructor.constructor('alert(1)')()}}",
}

var negatives = []string{
	"<p>hello <b>world</b></p>",
	"<h1>Title</h1><p>Some <em>text</em> here.</p>",
	"<a href=\"https://example.com/page?x=1&y=2\">link</a>",
	"<a href=\"/relative/path\">home</a>",
	"<a href=\"mailto:me@example.com\">mail</a>",
	"<a href=\"tel:+15551234\">call</a>",
	"<img src=\"/img/photo.jpg\" alt=\"a photo\">",
	"<img src=\"https://cdn.example.com/x.png\">",
	"<div class=\"container\" id=\"main\">content</div>",
	"<ul><li>one</li><li>two</li></ul>",
	"i think 3 < 5 and 5 > 3",
	"use url(image.png) in your css",
	"the xmlns attribute is for namespaces",
	"window.name is a browser property",
	"document.title returns the title",
	"a &amp; b &lt; c",
	"function onload() { return true; }",
	"the onclick handler in my code",
	"price < 100 or price > 50",
	"<blockquote>a quote</blockquote>",
	"<table><tr><td>cell</td></tr></table>",
	"<code>const x = &lt;T&gt;()</code>",
	"visit https://site.com for more",
	"email: user@domain.com",
	"5 > 3 ? yes : no",
	"json: {\"a\": 1, \"b\": [2,3]}",
	"my data: {name: 'bob'}",
	"see <example> for a placeholder",
	"a < b > c in math",
	"span of control",
	"the video loaded fine",
	"style guide for writing",
	"background information",
	"<span>plain text span</span>",
	"<strong>bold</strong> and <i>italic</i>",
	"click the link below",
	"data:image/png is fine as text",
	"<br><hr>",
}

func TestPositives(t *testing.T) {
	for _, p := range positives {
		if _, ok := Detect([]byte(p)); !ok {
			t.Errorf("MISS: %q", p)
		}
	}
}

func TestNegatives(t *testing.T) {
	for _, n := range negatives {
		if r, ok := Detect([]byte(n)); ok {
			t.Errorf("FALSE POSITIVE: %q -> %s", n, r.Reason)
		}
	}
}

func FuzzDetect(f *testing.F) {
	for _, p := range positives {
		f.Add(p)
	}
	for _, n := range negatives {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, s string) { Detect([]byte(s)) })
}

func BenchmarkDetectBenign(b *testing.B) {
	in := []byte("<p>hello <b>world</b></p> visit https://example.com/page?x=1")
	for i := 0; i < b.N; i++ {
		Detect(in)
	}
}

func BenchmarkDetectAttack(b *testing.B) {
	in := []byte("<img src=x onerror=alert(document.cookie)>")
	for i := 0; i < b.N; i++ {
		Detect(in)
	}
}
