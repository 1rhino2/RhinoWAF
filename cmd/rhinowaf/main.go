package main

import (
	"fmt"
	"log"
	"net/http"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/geo"
)

func main() {
	ddos.InitLogger(nil)

	// Initialize IP manager with advanced rules
	if err := ddos.InitIPManager("./config/ip_rules.json", true); err != nil {
		log.Printf("Warning: Failed to init IP manager: %v", err)
	}

	// Load GeoIP database
	if err := geo.LoadGeoDatabase("./config/geoip.json"); err != nil {
		log.Printf("Warning: Failed to load GeoIP database: %v", err)
	}

	http.HandleFunc("/", waf.AdaptiveProtect(handlers.Home))
	http.HandleFunc("/login", waf.AdaptiveProtect(handlers.Login))
	http.HandleFunc("/echo", waf.AdaptiveProtect(handlers.Echo))
	http.HandleFunc("/flood", waf.AdaptiveProtect(handlers.Flood))
	fmt.Println("RhinoWAF on :8080")
	fmt.Println("DDoS attack logs: ./logs/ddos.log")
	http.ListenAndServe(":8080", nil)
}
