package exemptions

import (
	"net"
	"strings"
	"sync"
)

type Config struct {
	Enabled    bool
	IPs        []string
	CIDRs      []string
	UserAgents []string
	Paths      []string
}

type Handler struct {
	config  Config
	ipNets  []*net.IPNet
	ipCache map[string]bool
	cacheMu sync.RWMutex
}

func NewHandler(config Config) (*Handler, error) {
	h := &Handler{
		config:  config,
		ipNets:  make([]*net.IPNet, 0),
		ipCache: make(map[string]bool),
	}

	for _, cidr := range config.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		h.ipNets = append(h.ipNets, ipNet)
	}

	return h, nil
}

func (h *Handler) IsExempt(ip, userAgent, path string) bool {
	if !h.config.Enabled {
		return false
	}

	if h.isIPExempt(ip) {
		return true
	}

	if h.isUserAgentExempt(userAgent) {
		return true
	}

	if h.isPathExempt(path) {
		return true
	}

	return false
}

func (h *Handler) isIPExempt(ip string) bool {
	h.cacheMu.RLock()
	if exempt, found := h.ipCache[ip]; found {
		h.cacheMu.RUnlock()
		return exempt
	}
	h.cacheMu.RUnlock()

	exempt := false

	for _, exemptIP := range h.config.IPs {
		if ip == exemptIP {
			exempt = true
			break
		}
	}

	if !exempt {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			for _, ipNet := range h.ipNets {
				if ipNet.Contains(parsedIP) {
					exempt = true
					break
				}
			}
		}
	}

	h.cacheMu.Lock()
	h.ipCache[ip] = exempt
	h.cacheMu.Unlock()

	return exempt
}

func (h *Handler) isUserAgentExempt(userAgent string) bool {
	userAgent = strings.ToLower(userAgent)
	for _, exemptUA := range h.config.UserAgents {
		if strings.Contains(userAgent, strings.ToLower(exemptUA)) {
			return true
		}
	}
	return false
}

func (h *Handler) isPathExempt(path string) bool {
	for _, exemptPath := range h.config.Paths {
		if strings.HasPrefix(path, exemptPath) {
			return true
		}
	}
	return false
}
