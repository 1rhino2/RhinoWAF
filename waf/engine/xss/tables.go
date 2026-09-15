package xss

// alwaysDanger fires on tag presence alone: these run script or load remote
// content just by being parsed. plain <p>, <b>, and even <img>/<a> are not
// here, they only bite through an on* handler or a script-scheme url, so a
// CMS body of "<p>hello <b>world</b></p>" or "<img src=/photo.jpg>" is clean.
var alwaysDanger = map[string]bool{
	"script": true, "iframe": true, "object": true, "embed": true, "base": true,
	"meta": true, "link": true, "style": true, "form": true, "frame": true,
	"frameset": true, "applet": true, "isindex": true, "keygen": true, "portal": true,
	"webview": true, "import": true, "template": true, "handler": true, "eventsource": true,
	"listener": true, "maction": true, "foreignobject": true,
}

// attributes that take a url we care about. a value that resolves to a
// script scheme in one of these is the actual vector.
var urlAttrs = map[string]bool{
	"src": true, "href": true, "xlink:href": true, "action": true, "formaction": true,
	"data": true, "poster": true, "background": true, "dynsrc": true, "lowsrc": true,
	"cite": true, "longdesc": true, "usemap": true, "profile": true, "manifest": true,
	"srcdoc": true, "srcset": true, "code": true, "codebase": true, "to": true, "from": true, "values": true,
}

// script schemes, checked after entity decode + control byte strip
var dangerSchemes = []string{"javascript:", "vbscript:", "livescript:", "mocha:", "data:text/html", "data:application", "data:image/svg"}
