package main

import (
	"fmt"
	"net/http"
	"rhinowaf/handlers"
	"rhinowaf/waf"
)

func main() {
	http.HandleFunc("/", waf.AdaptiveProtect(handlers.Home))
	http.HandleFunc("/login", waf.AdaptiveProtect(handlers.Login))
	http.HandleFunc("/echo", waf.AdaptiveProtect(handlers.Echo))
	http.HandleFunc("/flood", waf.AdaptiveProtect(handlers.Flood))
	fmt.Println("RhinoWAF on :8080")
	http.ListenAndServe(":8080", nil)
} // Dont you skid kid, or I will devour your family line.
