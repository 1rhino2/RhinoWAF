package reload

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"rhinowaf/waf/ddos"
	"rhinowaf/waf/geo"
	"rhinowaf/waf/metrics"

	"github.com/fsnotify/fsnotify"
)

// Manager handles configuration file watching and hot-reloading
type Manager struct {
	watcher        *fsnotify.Watcher
	ipRulesPath    string
	geoDBPath      string
	mu             sync.RWMutex
	lastReload     map[string]time.Time
	reloadDebounce time.Duration
	stopChan       chan struct{}
}

// Config holds reload manager configuration
type Config struct {
	IPRulesPath  string
	GeoDBPath    string
	DebounceTime time.Duration // Minimum time between reloads for same file
	WatchEnabled bool          // Enable automatic file watching
}

// NewManager creates a new reload manager
func NewManager(config Config) (*Manager, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Set default debounce time if not specified
	if config.DebounceTime == 0 {
		config.DebounceTime = 2 * time.Second
	}

	m := &Manager{
		watcher:        watcher,
		ipRulesPath:    config.IPRulesPath,
		geoDBPath:      config.GeoDBPath,
		lastReload:     make(map[string]time.Time),
		reloadDebounce: config.DebounceTime,
		stopChan:       make(chan struct{}),
	}

	// Add files to watch if enabled
	if config.WatchEnabled {
		if config.IPRulesPath != "" {
			if err := m.watchFile(config.IPRulesPath); err != nil {
				log.Printf("Warning: Could not watch IP rules file - %v (automatic reloads will be unavailable)", err)
			} else {
				log.Printf("Now monitoring IP rules file for changes: %s", config.IPRulesPath)
			}
		}

		if config.GeoDBPath != "" {
			if err := m.watchFile(config.GeoDBPath); err != nil {
				log.Printf("Warning: Could not watch GeoIP database file - %v (automatic reloads will be unavailable)", err)
			} else {
				log.Printf("Now monitoring GeoIP database for changes: %s", config.GeoDBPath)
			}
		}

		// Start watching in background
		go m.watch()
	}

	return m, nil
}

// watchFile adds a file to the watcher
func (m *Manager) watchFile(path string) error {
	// Watch the directory containing the file (for atomic writes)
	dir := filepath.Dir(path)
	return m.watcher.Add(dir)
}

// watch monitors file system events
func (m *Manager) watch() {
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Handle file write/create events
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				m.handleFileChange(event.Name)
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("File watcher error: %v", err)

		case <-m.stopChan:
			return
		}
	}
}

// handleFileChange processes file change events
func (m *Manager) handleFileChange(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if this is a file we're watching
	var reloadFunc func() error
	var fileType string

	if filepath.Base(path) == filepath.Base(m.ipRulesPath) {
		reloadFunc = m.reloadIPRules
		fileType = "ip_rules"
	} else if filepath.Base(path) == filepath.Base(m.geoDBPath) {
		reloadFunc = m.reloadGeoDatabase
		fileType = "geoip"
	} else {
		// Not a file we care about
		return
	}

	// Check debounce
	lastReload, exists := m.lastReload[fileType]
	if exists && time.Since(lastReload) < m.reloadDebounce {
		log.Printf("Skipping reload of %s configuration (too soon after last reload)", fileType)
		return
	}

	// Reload the configuration
	log.Printf("Configuration file changed, reloading %s...", fileType)
	if err := reloadFunc(); err != nil {
		log.Printf("Error: Failed to reload %s configuration - %v", fileType, err)
		return
	}

	m.lastReload[fileType] = time.Now()
	log.Printf("Successfully reloaded %s configuration", fileType)

	// Update metrics
	metrics.ConfigReloads.WithLabelValues(fileType).Inc()
}

// reloadIPRules reloads the IP rules configuration
func (m *Manager) reloadIPRules() error {
	// Validate file exists and is readable
	if _, err := os.Stat(m.ipRulesPath); err != nil {
		return fmt.Errorf("cannot access IP rules file: %w", err)
	}

	// Read and validate JSON
	data, err := os.ReadFile(m.ipRulesPath)
	if err != nil {
		return fmt.Errorf("failed to read IP rules: %w", err)
	}

	// Validate JSON structure
	var tempRules map[string]interface{}
	if err := json.Unmarshal(data, &tempRules); err != nil {
		return fmt.Errorf("invalid JSON in IP rules: %w", err)
	}

	// Reinitialize IP manager with new rules
	if err := ddos.InitIPManager(m.ipRulesPath, true); err != nil {
		return fmt.Errorf("failed to reinitialize IP manager: %w", err)
	}

	return nil
}

// reloadGeoDatabase reloads the GeoIP database
func (m *Manager) reloadGeoDatabase() error {
	// Validate file exists and is readable
	if _, err := os.Stat(m.geoDBPath); err != nil {
		return fmt.Errorf("cannot access GeoIP database: %w", err)
	}

	// Read and validate JSON
	data, err := os.ReadFile(m.geoDBPath)
	if err != nil {
		return fmt.Errorf("failed to read GeoIP database: %w", err)
	}

	// Validate JSON structure (could be array or object)
	var tempDB interface{}
	if err := json.Unmarshal(data, &tempDB); err != nil {
		return fmt.Errorf("invalid JSON in GeoIP database: %w", err)
	}

	// Reload GeoIP database
	if err := geo.LoadGeoDatabase(m.geoDBPath); err != nil {
		return fmt.Errorf("failed to reload GeoIP database: %w", err)
	}

	return nil
}

// ReloadAll manually reloads all watched configurations
func (m *Manager) ReloadAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []string

	// Reload IP rules
	if m.ipRulesPath != "" {
		log.Printf("Reloading IP rules configuration...")
		if err := m.reloadIPRules(); err != nil {
			errors = append(errors, fmt.Sprintf("IP rules: %v", err))
			log.Printf("Error: Failed to reload IP rules - %v", err)
		} else {
			m.lastReload["ip_rules"] = time.Now()
			log.Printf("Successfully reloaded IP rules")
			metrics.ConfigReloads.WithLabelValues("ip_rules").Inc()
		}
	}

	// Reload GeoIP database
	if m.geoDBPath != "" {
		log.Printf("Reloading GeoIP database...")
		if err := m.reloadGeoDatabase(); err != nil {
			errors = append(errors, fmt.Sprintf("GeoIP: %v", err))
			log.Printf("Error: Failed to reload GeoIP database - %v", err)
		} else {
			m.lastReload["geoip"] = time.Now()
			log.Printf("Successfully reloaded GeoIP database")
			metrics.ConfigReloads.WithLabelValues("geoip").Inc()
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("reload errors: %v", errors)
	}

	return nil
}

// GetLastReloadTime returns the last reload time for a specific config type
func (m *Manager) GetLastReloadTime(configType string) (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, exists := m.lastReload[configType]
	return t, exists
}

// GetStatus returns the current status of the reload manager
func (m *Manager) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := map[string]interface{}{
		"ip_rules_path": m.ipRulesPath,
		"geodb_path":    m.geoDBPath,
		"debounce_time": m.reloadDebounce.String(),
		"last_reloads":  make(map[string]string),
	}

	for configType, lastTime := range m.lastReload {
		if lastReloads, ok := status["last_reloads"].(map[string]string); ok {
			lastReloads[configType] = lastTime.Format(time.RFC3339)
		}
	}

	return status
}

// Stop stops the file watcher
func (m *Manager) Stop() error {
	close(m.stopChan)
	return m.watcher.Close()
}
