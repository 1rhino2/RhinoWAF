package waf

import (
	"net/http"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/sanitize"
)

func AdaptiveProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ddos.GetIP(r)
		if !ddos.AllowL7(ip) || !ddos.AllowL4(ip) {
			http.Error(w, "RhinoWAF: Attack Diffused/Mitigated", http.StatusTooManyRequests)
			return
		}
		sanitize.All(r)
		if sanitize.IsMalicious(r) {
			http.Error(w, "RhinoWAF: Malicious input blocked", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
