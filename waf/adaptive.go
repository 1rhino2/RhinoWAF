package waf

import (
	"net/http"
)

func AdaptiveProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ProtectRequest(w, r) {
			return
		}
		next(w, r)
	}
}
