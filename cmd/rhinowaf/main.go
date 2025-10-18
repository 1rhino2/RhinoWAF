package main

import (
	"fmt"
	"net/http"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/ddos"
)

func main() {
	// Initialize DDoS attack logger with default settings
	// Logs will be written to ./logs/ddos.log in JSON format
	ddos.InitLogger(nil)

	http.HandleFunc("/", waf.AdaptiveProtect(handlers.Home))
	http.HandleFunc("/login", waf.AdaptiveProtect(handlers.Login))
	http.HandleFunc("/echo", waf.AdaptiveProtect(handlers.Echo))
	http.HandleFunc("/flood", waf.AdaptiveProtect(handlers.Flood))
	fmt.Println("RhinoWAF on :8080")
	fmt.Println("DDoS attack logs: ./logs/ddos.log")
	http.ListenAndServe(":8080", nil)
} // Dont you skid kid, or I will devour your family line.
