package main

import (
	"fmt"
	"net/http"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/ddos"
)

func main() {
	ddos.InitLogger(nil)

	http.HandleFunc("/", waf.AdaptiveProtect(handlers.Home))
	http.HandleFunc("/login", waf.AdaptiveProtect(handlers.Login))
	http.HandleFunc("/echo", waf.AdaptiveProtect(handlers.Echo))
	http.HandleFunc("/flood", waf.AdaptiveProtect(handlers.Flood))
	fmt.Println("RhinoWAF on :8080")
	fmt.Println("DDoS attack logs: ./logs/ddos.log")
	http.ListenAndServe(":8080", nil)
}
