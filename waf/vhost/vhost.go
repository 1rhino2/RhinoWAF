package vhost

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
)

type BackendConfig struct {
	Domain  string `json:"domain"`
	Backend string `json:"backend"`
	Enabled bool   `json:"enabled"`
}

type VHostConfig struct {
	Backends       []BackendConfig `json:"backends"`
	DefaultBackend string          `json:"default_backend,omitempty"`
}

type VHostManager struct {
	config  *VHostConfig
	proxies map[string]*httputil.ReverseProxy
	mu      sync.RWMutex
}

func NewVHostManager(configPath string) (*VHostManager, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vhost config: %w", err)
	}

	var config VHostConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse vhost config: %w", err)
	}

	mgr := &VHostManager{
		config:  &config,
		proxies: make(map[string]*httputil.ReverseProxy),
	}

	if err := mgr.initProxies(); err != nil {
		return nil, err
	}

	return mgr, nil
}

func (m *VHostManager) initProxies() error {
	for _, backend := range m.config.Backends {
		if !backend.Enabled {
			continue
		}

		if backend.Domain == "" {
			return fmt.Errorf("empty domain not allowed")
		}

		if backend.Backend == "" {
			return fmt.Errorf("backend URL required for domain %s", backend.Domain)
		}

		targetURL, err := url.Parse(backend.Backend)
		if err != nil {
			return fmt.Errorf("invalid backend URL for %s: %w", backend.Domain, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Backend error for %s -> %s: %v", backend.Domain, backend.Backend, err)
			http.Error(w, "Backend unavailable", http.StatusBadGateway)
		}

		m.proxies[strings.ToLower(backend.Domain)] = proxy
		log.Printf("Configured vhost: %s -> %s", backend.Domain, backend.Backend)
	}

	if m.config.DefaultBackend != "" {
		targetURL, err := url.Parse(m.config.DefaultBackend)
		if err != nil {
			return fmt.Errorf("invalid default backend URL: %w", err)
		}
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Default backend error: %v", err)
			http.Error(w, "Backend unavailable", http.StatusBadGateway)
		}
		m.proxies["__default__"] = proxy
		log.Printf("Configured default backend: %s", m.config.DefaultBackend)
	}

	return nil
}

func (m *VHostManager) GetProxy(host string) *httputil.ReverseProxy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hostOnly := strings.Split(host, ":")[0]
	hostLower := strings.ToLower(hostOnly)

	if proxy, ok := m.proxies[hostLower]; ok {
		return proxy
	}

	if defaultProxy, ok := m.proxies["__default__"]; ok {
		return defaultProxy
	}

	return nil
}

func (m *VHostManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxy := m.GetProxy(r.Host)
	if proxy == nil {
		log.Printf("No backend configured for host: %s", r.Host)
		http.Error(w, "No backend configured for this domain", http.StatusNotFound)
		return
	}

	proxy.ServeHTTP(w, r)
}

func (m *VHostManager) Reload(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read vhost config: %w", err)
	}

	var newConfig VHostConfig
	if err := json.Unmarshal(data, &newConfig); err != nil {
		return fmt.Errorf("failed to parse vhost config: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	oldProxies := m.proxies
	m.proxies = make(map[string]*httputil.ReverseProxy)
	m.config = &newConfig

	if err := m.initProxies(); err != nil {
		m.proxies = oldProxies
		return fmt.Errorf("failed to reinitialize proxies: %w", err)
	}

	log.Println("VHost configuration reloaded successfully")
	return nil
}

func (m *VHostManager) GetBackends() []BackendConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Backends
}

func (m *VHostManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domains := make([]string, 0, len(m.proxies))
	for domain := range m.proxies {
		if domain != "__default__" {
			domains = append(domains, domain)
		}
	}

	return map[string]interface{}{
		"total_backends":  len(domains),
		"configured_domains": domains,
		"has_default_backend": m.config.DefaultBackend != "",
	}
}
