package security

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustedProxyConfig defines which proxies we trust for X-Forwarded-For
type TrustedProxyConfig struct {
	TrustedCIDRs []*net.IPNet
	TrustAll     bool
}

var defaultConfig = &TrustedProxyConfig{
	TrustedCIDRs: []*net.IPNet{
		mustParseCIDR("127.0.0.0/8"),
		mustParseCIDR("::1/128"),
		mustParseCIDR("10.0.0.0/8"),
		mustParseCIDR("172.16.0.0/12"),
		mustParseCIDR("192.168.0.0/16"),
		mustParseCIDR("fc00::/7"),
	},
	TrustAll: false,
}

var currentConfig = defaultConfig

func SetTrustedProxies(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		nets = append(nets, ipnet)
	}
	currentConfig = &TrustedProxyConfig{
		TrustedCIDRs: nets,
		TrustAll:     false,
	}
	return nil
}

func GetRealIP(r *http.Request) string {
	remoteIP := getRemoteIP(r)
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return remoteIP
	}

	if !currentConfig.TrustAll && !isTrustedProxy(ip) {
		return remoteIP
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(parts[0])
		if parsed := net.ParseIP(clientIP); parsed != nil {
			return clientIP
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if parsed := net.ParseIP(xri); parsed != nil {
			return xri
		}
	}

	return remoteIP
}

func getRemoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isTrustedProxy(ip net.IP) bool {
	for _, cidr := range currentConfig.TrustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

func NormalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}

	if parsed.To4() != nil {
		return parsed.To4().String()
	}

	return parsed.To16().String()
}

func IsIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil
}

func IsIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IPv6 subnet support
func ParseIPWithSubnet(ipStr string) (net.IP, *net.IPNet, error) {
	if strings.Contains(ipStr, "/") {
		ip, ipnet, err := net.ParseCIDR(ipStr)
		return ip, ipnet, err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	return ip, nil, nil
}

// IsIPv6LinkLocal checks if an IPv6 address is link-local (fe80::/10)
func IsIPv6LinkLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return false
	}
	return parsed.IsLinkLocalUnicast()
}

// IsIPv6UniqueLocal checks if an IPv6 address is unique local (fc00::/7)
func IsIPv6UniqueLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return false
	}
	p := parsed.To16()
	return p != nil && (p[0]&0xfe) == 0xfc
}

// IsIPv6Loopback checks if address is IPv6 loopback (::1)
func IsIPv6Loopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() && parsed.To4() == nil
}

// ExpandIPv6 expands an IPv6 address to full form
func ExpandIPv6(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	p := parsed.To16()
	if p == nil {
		return ip
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15])
}

// IsPrivateIP checks if an IP (v4 or v6) is in a private range
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	if parsed.To4() != nil {
		return parsed.IsPrivate() || parsed.IsLoopback()
	}

	// IPv6 private ranges
	return IsIPv6UniqueLocal(ip) || IsIPv6LinkLocal(ip) || IsIPv6Loopback(ip)
}

// GetIPVersion returns 4, 6, or 0 for invalid
func GetIPVersion(ip string) int {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	if parsed.To4() != nil {
		return 4
	}
	return 6
}
