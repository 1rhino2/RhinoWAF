package waf

import (
	"net"
	"net/http"
	"rhinowaf/waf/security"
)

// Only allow requests from localhost (127.0.0.0/8 or ::1). Goes through the
// trusted-proxy aware client IP so a local reverse proxy forwarding for a
// remote user doesn't open the admin endpoints up.
func LocalhostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parsedIP := net.ParseIP(security.GetRealIP(r))
		if parsedIP == nil || !parsedIP.IsLoopback() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
