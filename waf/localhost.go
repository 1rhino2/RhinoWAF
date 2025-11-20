package waf

import (
	"net"
	"net/http"
)

// Only allow requests from localhost (127.0.0.1 or ::1)
func LocalhostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// parse and normalize IP to handle compressed/expanded IPv6
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// check for localhost addresses
		if parsedIP.IsLoopback() && (parsedIP.String() == "127.0.0.1" || parsedIP.To4() == nil) {
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}
