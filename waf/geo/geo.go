package geo

import (
	"encoding/json"
	"net"
	"os"
	"sync"
)

type GeoData struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	Proxy       bool   `json:"proxy"`
	VPN         bool   `json:"vpn"`
	Tor         bool   `json:"tor"`
	Hosting     bool   `json:"hosting"`
}

type IPRange struct {
	CIDR        string `json:"cidr"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	network     *net.IPNet
}

type GeoIP struct {
	mu         sync.RWMutex
	ranges     []IPRange
	cache      map[string]*GeoData
	cacheSize  int
	cacheCount int
}

var geoIP *GeoIP

func init() {
	geoIP = &GeoIP{
		ranges:    make([]IPRange, 0),
		cache:     make(map[string]*GeoData),
		cacheSize: 10000,
	}
}

func LoadGeoDatabase(path string) error {
	if path == "" {
		path = "./config/geoip.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return geoIP.createDefaultDatabase(path)
		}
		return err
	}

	geoIP.mu.Lock()
	defer geoIP.mu.Unlock()

	var ranges []IPRange
	if err := json.Unmarshal(data, &ranges); err != nil {
		return err
	}

	for i := range ranges {
		_, network, err := net.ParseCIDR(ranges[i].CIDR)
		if err != nil {
			continue
		}
		ranges[i].network = network
	}

	geoIP.ranges = ranges
	return nil
}

func Lookup(ip string) *GeoData {
	geoIP.mu.RLock()
	if cached, ok := geoIP.cache[ip]; ok {
		geoIP.mu.RUnlock()
		return cached
	}
	geoIP.mu.RUnlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &GeoData{IP: ip, CountryCode: "XX", CountryName: "Unknown"}
	}

	geoIP.mu.RLock()
	defer geoIP.mu.RUnlock()

	for _, ipRange := range geoIP.ranges {
		if ipRange.network != nil && ipRange.network.Contains(parsedIP) {
			geo := &GeoData{
				IP:          ip,
				CountryCode: ipRange.CountryCode,
				CountryName: ipRange.CountryName,
			}
			geoIP.addToCache(ip, geo)
			return geo
		}
	}

	geo := &GeoData{IP: ip, CountryCode: "XX", CountryName: "Unknown"}
	geoIP.addToCache(ip, geo)
	return geo
}

func (g *GeoIP) addToCache(ip string, data *GeoData) {
	if g.cacheCount >= g.cacheSize {
		g.cache = make(map[string]*GeoData)
		g.cacheCount = 0
	}
	g.cache[ip] = data
	g.cacheCount++
}

func GetCountryCode(ip string) string {
	geo := Lookup(ip)
	return geo.CountryCode
}

func IsProxy(ip string) bool {
	geo := Lookup(ip)
	return geo.Proxy || geo.VPN || geo.Tor || geo.Hosting
}

func ClearCache() {
	geoIP.mu.Lock()
	defer geoIP.mu.Unlock()
	geoIP.cache = make(map[string]*GeoData)
}

func AddRange(cidr, countryCode, countryName string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	geoIP.mu.Lock()
	defer geoIP.mu.Unlock()

	geoIP.ranges = append(geoIP.ranges, IPRange{
		CIDR:        cidr,
		CountryCode: countryCode,
		CountryName: countryName,
		network:     network,
	})

	return nil
}

func (g *GeoIP) createDefaultDatabase(path string) error {
	defaultRanges := []IPRange{
		{CIDR: "127.0.0.0/8", CountryCode: "ZZ", CountryName: "Localhost"},
		{CIDR: "10.0.0.0/8", CountryCode: "ZZ", CountryName: "Private"},
		{CIDR: "172.16.0.0/12", CountryCode: "ZZ", CountryName: "Private"},
		{CIDR: "192.168.0.0/16", CountryCode: "ZZ", CountryName: "Private"},
		{CIDR: "::1/128", CountryCode: "ZZ", CountryName: "Localhost (IPv6)"},
		{CIDR: "fc00::/7", CountryCode: "ZZ", CountryName: "Private (IPv6 ULA)"},
		{CIDR: "fe80::/10", CountryCode: "ZZ", CountryName: "Private (IPv6 Link-Local)"},
		{CIDR: "ff00::/8", CountryCode: "ZZ", CountryName: "Multicast (IPv6)"},
	}

	data, err := json.MarshalIndent(defaultRanges, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
