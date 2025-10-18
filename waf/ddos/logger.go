package ddos

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DDoSEvent represents a detailed DDoS attack event with enhanced metadata
type DDoSEvent struct {
	Timestamp     string `json:"timestamp"`
	EventType     string `json:"event_type"`
	IP            string `json:"ip"`
	Severity      string `json:"severity"`
	BlockDuration int    `json:"block_duration_sec"`

	// Request details
	RequestCount      int `json:"request_count"`
	ConnectionCount   int `json:"connection_count"`
	ActiveConnections int `json:"active_connections"`

	// IP reputation and history
	Reputation     int    `json:"reputation"`
	ViolationCount int    `json:"violation_count"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
	PreviousBlocks int    `json:"previous_blocks"`

	// Attack specifics
	RateLimit        int  `json:"rate_limit"`
	ActualRate       int  `json:"actual_rate"`
	ExcessPercentage int  `json:"excess_percentage"`
	BurstDetected    bool `json:"burst_detected"`
	SlowConnWarnings int  `json:"slow_connection_warnings"`

	// Enhanced metadata
	UserAgent    string `json:"user_agent,omitempty"`
	Path         string `json:"path,omitempty"`
	Method       string `json:"method,omitempty"`
	Referer      string `json:"referer,omitempty"`
	Host         string `json:"host,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	ResponseCode int    `json:"response_code,omitempty"`

	// Connection details
	ConnectionID       string `json:"connection_id,omitempty"`
	BytesSent          int64  `json:"bytes_sent,omitempty"`
	BytesReceived      int64  `json:"bytes_received,omitempty"`
	ConnectionDuration int    `json:"connection_duration_ms,omitempty"`

	// Geolocation (if available)
	Country string `json:"country,omitempty"`
	ASN     string `json:"asn,omitempty"`
	ISP     string `json:"isp,omitempty"`

	// Distributed attack context
	GlobalRPS          int     `json:"global_rps,omitempty"`
	ActiveIPCount      int     `json:"active_ip_count,omitempty"`
	SuspiciousIPCount  int     `json:"suspicious_ip_count,omitempty"`
	ThrottleLevel      int     `json:"throttle_level,omitempty"`
	ThrottleMultiplier float64 `json:"throttle_multiplier,omitempty"`

	// Additional context
	Message           string            `json:"message"`
	RecommendedAction string            `json:"recommended_action"`
	Tags              []string          `json:"tags,omitempty"`
	CustomFields      map[string]string `json:"custom_fields,omitempty"`
}

// Logger handles DDoS event logging with buffering, rotation, and compression
type Logger struct {
	mu          sync.Mutex
	file        *os.File
	bufWriter   *bufio.Writer
	jsonEncoder *json.Encoder
	// Human-readable output
	humanFile    *os.File
	humanWriter  *bufio.Writer
	humanEnabled bool
	humanPath    string
	logPath      string
	enabled      bool
	logToConsole bool
	eventCount   int64
	byteCount    int64

	// Buffering and rotation
	flushTimer    *time.Ticker
	rotationTimer *time.Ticker
	maxSizeMB     int
	maxAgeDays    int
	compressOld   bool
	flushInterval time.Duration
	batchSize     int
	eventBuffer   []interface{}
}

var (
	ddosLogger     *Logger
	loggerInitOnce sync.Once
)

// LoggerConfig configures the DDoS logger with enterprise features
type LoggerConfig struct {
	LogPath       string
	Enabled       bool
	LogToConsole  bool
	MaxSizeMB     int
	MaxAgeDays    int
	CompressOld   bool
	FlushInterval time.Duration
	BatchSize     int
	// Human-readable log options
	HumanReadableEnabled bool
	HumanReadablePath    string
}

// InitLogger initializes the DDoS logger with enterprise features
func InitLogger(config *LoggerConfig) error {
	var initErr error

	loggerInitOnce.Do(func() {
		if config == nil {
			config = &LoggerConfig{
				LogPath:              "./logs/ddos.log",
				Enabled:              true,
				LogToConsole:         false,
				MaxSizeMB:            100,
				MaxAgeDays:           30,
				CompressOld:          true,
				FlushInterval:        1 * time.Second,
				BatchSize:            100,
				HumanReadableEnabled: true,
				HumanReadablePath:    "./logs/ddos_readable.log",
			}
		}

		if !config.Enabled {
			ddosLogger = &Logger{enabled: false}
			return
		}

		logDir := filepath.Dir(config.LogPath)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			initErr = fmt.Errorf("failed to create log directory: %w", err)
			return
		}

		file, err := os.OpenFile(config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			initErr = fmt.Errorf("failed to open log file: %w", err)
			return
		}

		bufWriter := bufio.NewWriterSize(file, 64*1024)

		// Optional human-readable log
		var humanFile *os.File
		var humanWriter *bufio.Writer
		if config.HumanReadableEnabled {
			if config.HumanReadablePath == "" {
				config.HumanReadablePath = filepath.Join(logDir, "ddos_readable.log")
			}
			hf, herr := os.OpenFile(config.HumanReadablePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if herr != nil {
				// Don't fail initialization due to human-readable log issues; just disable it
				log.Printf("Warning: failed to open human-readable log: %v", herr)
			} else {
				humanFile = hf
				humanWriter = bufio.NewWriterSize(hf, 64*1024)
			}
		}

		ddosLogger = &Logger{
			file:          file,
			bufWriter:     bufWriter,
			jsonEncoder:   json.NewEncoder(bufWriter),
			humanFile:     humanFile,
			humanWriter:   humanWriter,
			humanEnabled:  humanWriter != nil,
			humanPath:     config.HumanReadablePath,
			logPath:       config.LogPath,
			enabled:       true,
			logToConsole:  config.LogToConsole,
			eventCount:    0,
			byteCount:     0,
			maxSizeMB:     config.MaxSizeMB,
			maxAgeDays:    config.MaxAgeDays,
			compressOld:   config.CompressOld,
			flushInterval: config.FlushInterval,
			batchSize:     config.BatchSize,
			eventBuffer:   make([]interface{}, 0, config.BatchSize),
			flushTimer:    time.NewTicker(config.FlushInterval),
			rotationTimer: time.NewTicker(1 * time.Hour),
		}

		go ddosLogger.backgroundFlusher()
		go ddosLogger.backgroundRotator()
		ddosLogger.cleanupOldLogs()

		initEvent := map[string]interface{}{
			"timestamp":      time.Now().Format(time.RFC3339),
			"event":          "logger_initialized",
			"log_path":       config.LogPath,
			"human_readable": config.HumanReadableEnabled,
			"human_path":     config.HumanReadablePath,
			"max_size_mb":    config.MaxSizeMB,
			"max_age_days":   config.MaxAgeDays,
			"compress_old":   config.CompressOld,
			"flush_interval": config.FlushInterval.String(),
			"batch_size":     config.BatchSize,
		}
		ddosLogger.writeJSONBuffered(initEvent)
	})

	return initErr
}

// GetLogger returns the global DDoS logger instance
func GetLogger() *Logger {
	if ddosLogger == nil {
		InitLogger(nil)
	}
	return ddosLogger
}

// LogRateLimitViolation logs a rate limiting event
func LogRateLimitViolation(ip string, entry *IPEntry, isLayer7 bool, actualRate, limit int) {
	logger := GetLogger()
	if !logger.enabled {
		return
	}

	layerType := "L4"
	eventType := "l4_flood"
	if isLayer7 {
		layerType = "L7"
		eventType = "rate_limit"
	}

	severity := "medium"
	excessPercent := ((actualRate - limit) * 100) / limit
	if excessPercent > 200 {
		severity = "critical"
	} else if excessPercent > 100 {
		severity = "high"
	}

	event := DDoSEvent{
		Timestamp:         time.Now().Format(time.RFC3339),
		EventType:         eventType,
		IP:                ip,
		Severity:          severity,
		BlockDuration:     cfg.BlockDurationSec,
		RequestCount:      len(entry.Requests),
		ConnectionCount:   len(entry.Connections),
		ActiveConnections: len(entry.ActiveConns),
		Reputation:        entry.Reputation,
		ViolationCount:    entry.ViolationCount,
		FirstSeen:         time.Unix(entry.FirstSeen, 0).Format(time.RFC3339),
		LastSeen:          time.Unix(entry.LastSeen, 0).Format(time.RFC3339),
		RateLimit:         limit,
		ActualRate:        actualRate,
		ExcessPercentage:  excessPercent,
		BurstDetected:     false,
		SlowConnWarnings:  entry.SlowConnWarnings,
		BytesSent:         entry.BytesSent,
		Message: fmt.Sprintf("%s rate limit exceeded: %d/%d requests (%d%% over limit)",
			layerType, actualRate, limit, excessPercent),
		RecommendedAction: determineAction(entry, excessPercent),
		Tags:              []string{layerType, "rate_limit"},
	}

	logger.logEvent(event)
}

// LogBurstAttack logs a burst attack event
func LogBurstAttack(ip string, entry *IPEntry, requestCount int) {
	logger := GetLogger()
	if !logger.enabled {
		return
	}

	excessPercent := ((requestCount - cfg.BurstLimit) * 100) / cfg.BurstLimit

	event := DDoSEvent{
		Timestamp:         time.Now().Format(time.RFC3339),
		EventType:         "burst",
		IP:                ip,
		Severity:          "critical",
		BlockDuration:     cfg.BlockDurationSec,
		RequestCount:      requestCount,
		ConnectionCount:   len(entry.Connections),
		ActiveConnections: len(entry.ActiveConns),
		Reputation:        entry.Reputation,
		ViolationCount:    entry.ViolationCount,
		FirstSeen:         time.Unix(entry.FirstSeen, 0).Format(time.RFC3339),
		LastSeen:          time.Unix(entry.LastSeen, 0).Format(time.RFC3339),
		RateLimit:         cfg.BurstLimit,
		ActualRate:        requestCount,
		ExcessPercentage:  excessPercent,
		BurstDetected:     true,
		SlowConnWarnings:  entry.SlowConnWarnings,
		BytesSent:         entry.BytesSent,
		Message: fmt.Sprintf("BURST ATTACK DETECTED: %d requests in rapid succession (limit: %d, %d%% over)",
			requestCount, cfg.BurstLimit, excessPercent),
		RecommendedAction: "IMMEDIATE_BLOCK - Consider permanent ban or CAPTCHA challenge",
		Tags:              []string{"burst", "critical_threat"},
	}

	logger.logEvent(event)
}

// LogSlowlorisAttack logs a Slowloris attack event
func LogSlowlorisAttack(ip string, entry *IPEntry, staleConnections int) {
	logger := GetLogger()
	if !logger.enabled {
		return
	}

	severity := "medium"
	if staleConnections >= cfg.SlowLorisMaxConnsPerIP/2 {
		severity = "high"
	}
	if staleConnections >= cfg.SlowLorisMaxConnsPerIP {
		severity = "critical"
	}

	event := DDoSEvent{
		Timestamp:         time.Now().Format(time.RFC3339),
		EventType:         "slowloris",
		IP:                ip,
		Severity:          severity,
		BlockDuration:     cfg.BlockDurationSec,
		RequestCount:      len(entry.Requests),
		ConnectionCount:   len(entry.Connections),
		ActiveConnections: len(entry.ActiveConns),
		Reputation:        entry.Reputation,
		ViolationCount:    entry.ViolationCount,
		FirstSeen:         time.Unix(entry.FirstSeen, 0).Format(time.RFC3339),
		LastSeen:          time.Unix(entry.LastSeen, 0).Format(time.RFC3339),
		SlowConnWarnings:  entry.SlowConnWarnings,
		BytesSent:         entry.BytesSent,
		Message: fmt.Sprintf("Slowloris attack detected: %d stale connections exceeding %ds timeout",
			staleConnections, cfg.SlowLorisMaxConnTime),
		RecommendedAction: "Monitor for distributed slow attacks. Consider stricter connection limits.",
		Tags:              []string{"slowloris", "slow_dos"},
	}

	logger.logEvent(event)
}

// LogReputationBlock logs when an IP is blocked due to poor reputation
func LogReputationBlock(ip string, entry *IPEntry) {
	logger := GetLogger()
	if !logger.enabled {
		return
	}

	event := DDoSEvent{
		Timestamp:         time.Now().Format(time.RFC3339),
		EventType:         "reputation",
		IP:                ip,
		Severity:          "high",
		BlockDuration:     cfg.BlockDurationSec * 2,
		RequestCount:      len(entry.Requests),
		ConnectionCount:   len(entry.Connections),
		ActiveConnections: len(entry.ActiveConns),
		Reputation:        entry.Reputation,
		ViolationCount:    entry.ViolationCount,
		FirstSeen:         time.Unix(entry.FirstSeen, 0).Format(time.RFC3339),
		LastSeen:          time.Unix(entry.LastSeen, 0).Format(time.RFC3339),
		PreviousBlocks:    entry.ViolationCount,
		SlowConnWarnings:  entry.SlowConnWarnings,
		BytesSent:         entry.BytesSent,
		Message: fmt.Sprintf("REPEAT OFFENDER: IP blocked due to poor reputation (%d, threshold: %d) after %d violations",
			entry.Reputation, cfg.ReputationThreshold, entry.ViolationCount),
		RecommendedAction: "Consider permanent ban. This IP has a history of attacks.",
		Tags:              []string{"reputation", "repeat_offender"},
	}

	logger.logEvent(event)
}

// LogGeoBlock logs when an IP is blocked due to geolocation
func LogGeoBlock(ip, countryCode string) {
	logger := GetLogger()
	if !logger.enabled {
		return
	}

	event := map[string]interface{}{
		"timestamp":    time.Now().Format(time.RFC3339),
		"event_type":   "geo_block",
		"ip":           ip,
		"country_code": countryCode,
		"severity":     "medium",
		"message":      fmt.Sprintf("IP blocked due to geolocation rule: %s", countryCode),
		"tags":         []string{"geoblocking", "access_control"},
	}

	logger.writeJSONBuffered(event)
}

// LogDistributedAttack logs when a distributed DDoS attack is detected
func LogDistributedAttack() {
	logger := GetLogger()
	if !logger.enabled {
		return
	}

	stats := globalTracker.GetGlobalStats()

	event := map[string]interface{}{
		"timestamp":           time.Now().Format(time.RFC3339),
		"event_type":          "distributed_ddos",
		"severity":            "critical",
		"total_requests":      stats["total_requests"],
		"current_rps":         stats["current_rps"],
		"active_ips":          stats["active_ips"],
		"active_connections":  stats["active_connections"],
		"suspicious_ips":      stats["suspicious_ips"],
		"throttle_level":      stats["throttle_level"],
		"throttle_multiplier": stats["throttle_multiplier"],
		"message":             fmt.Sprintf("Distributed DDoS attack detected: %d RPS from %d IPs (limit: %d RPS)", stats["current_rps"], stats["active_ips"], cfg.GlobalRateLimit),
		"recommended_action":  "Adaptive throttling enabled. Consider enabling upstream CDN (Cloudflare) for additional protection.",
		"tags":                []string{"distributed_ddos", "critical_threat", "multi_source"},
	}

	logger.writeJSONBuffered(event)
}

// LogAttackSummary logs a periodic summary of attacks
func LogAttackSummary(stats map[string]interface{}) {
	logger := GetLogger()
	if !logger.enabled {
		return
	}

	summary := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"event":         "attack_summary",
		"stats":         stats,
		"events_logged": logger.eventCount,
	}

	logger.writeJSONBuffered(summary)
}

// logEvent writes a DDoS event to the log file with buffering
func (l *Logger) logEvent(event DDoSEvent) {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	l.eventCount++
	l.eventBuffer = append(l.eventBuffer, event)

	if len(l.eventBuffer) >= l.batchSize {
		l.flushBuffer()
	}
	l.mu.Unlock()

	if l.logToConsole {
		log.Printf("[DDoS] [%s] %s - %s - %s\n",
			event.Severity, event.EventType, event.IP, event.Message)
	}
}

// writeJSONBuffered adds an event to the buffer
func (l *Logger) writeJSONBuffered(v interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.eventBuffer = append(l.eventBuffer, v)

	if len(l.eventBuffer) >= l.batchSize {
		l.flushBuffer()
	}
}

// flushBuffer writes all buffered events to disk (must be called with lock held)
func (l *Logger) flushBuffer() {
	if l.jsonEncoder == nil || len(l.eventBuffer) == 0 {
		return
	}

	for _, event := range l.eventBuffer {
		if err := l.jsonEncoder.Encode(event); err != nil {
			log.Printf("Failed to write DDoS log: %v", err)
		}
		if l.humanEnabled && l.humanWriter != nil {
			line := l.formatHumanLine(event)
			if _, err := l.humanWriter.WriteString(line + "\n"); err != nil {
				log.Printf("Failed to write human-readable log: %v", err)
			}
		}
	}

	l.eventBuffer = l.eventBuffer[:0]

	if l.bufWriter != nil {
		if err := l.bufWriter.Flush(); err != nil {
			log.Printf("Failed to flush log buffer: %v", err)
		}
	}

	if l.humanWriter != nil {
		if err := l.humanWriter.Flush(); err != nil {
			log.Printf("Failed to flush human-readable buffer: %v", err)
		}
	}

	if l.file != nil {
		l.file.Sync()
	}
	if l.humanFile != nil {
		l.humanFile.Sync()
	}
}

// backgroundFlusher periodically flushes the buffer to disk
func (l *Logger) backgroundFlusher() {
	for range l.flushTimer.C {
		l.mu.Lock()
		l.flushBuffer()
		l.mu.Unlock()
	}
}

// backgroundRotator checks for log rotation and cleanup
func (l *Logger) backgroundRotator() {
	for range l.rotationTimer.C {
		l.checkRotation()
		l.cleanupOldLogs()
	}
}

// checkRotation rotates log if it exceeds max size
func (l *Logger) checkRotation() {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	fileInfo, err := l.file.Stat()
	if err != nil {
		log.Printf("Failed to stat log file: %v", err)
		return
	}

	sizeMB := fileInfo.Size() / (1024 * 1024)
	if sizeMB < int64(l.maxSizeMB) {
		return
	}

	l.rotateLog()
}

// rotateLog creates a new log file and optionally compresses the old one
func (l *Logger) rotateLog() {
	if l.file == nil {
		return
	}

	l.flushBuffer()

	timestamp := time.Now().Format("20060102-150405")
	oldPath := l.logPath
	newPath := fmt.Sprintf("%s.%s", l.logPath, timestamp)

	rotateEvent := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"event":     "log_rotation",
		"old_size":  l.byteCount,
		"new_file":  newPath,
	}
	l.jsonEncoder.Encode(rotateEvent)
	if l.humanEnabled && l.humanWriter != nil {
		l.humanWriter.WriteString(l.formatHumanLine(rotateEvent) + "\n")
		l.humanWriter.Flush()
	}
	l.bufWriter.Flush()
	l.file.Close()

	if err := os.Rename(oldPath, newPath); err != nil {
		log.Printf("Failed to rotate log: %v", err)
		return
	}

	if l.compressOld {
		go l.compressLogFile(newPath)
	}

	file, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Failed to open new log file: %v", err)
		return
	}

	l.file = file
	l.bufWriter = bufio.NewWriterSize(file, 64*1024)
	l.jsonEncoder = json.NewEncoder(l.bufWriter)
	l.byteCount = 0

	marker := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"event":     "log_rotated",
		"from":      newPath,
	}
	l.jsonEncoder.Encode(marker)
	if l.humanEnabled && l.humanWriter != nil {
		l.humanWriter.WriteString(l.formatHumanLine(marker) + "\n")
		l.humanWriter.Flush()
	}
}

// compressLogFile compresses a log file with gzip
func (l *Logger) compressLogFile(filename string) {
	gzFilename := filename + ".gz"

	srcFile, err := os.Open(filename)
	if err != nil {
		log.Printf("Failed to open file for compression: %v", err)
		return
	}
	defer srcFile.Close()

	gzFile, err := os.Create(gzFilename)
	if err != nil {
		log.Printf("Failed to create gzip file: %v", err)
		return
	}
	defer gzFile.Close()

	gzWriter := gzip.NewWriter(gzFile)
	defer gzWriter.Close()

	if _, err := io.Copy(gzWriter, srcFile); err != nil {
		log.Printf("Failed to compress log: %v", err)
		return
	}

	os.Remove(filename)
	log.Printf("Compressed and removed old log: %s -> %s", filename, gzFilename)
}

// cleanupOldLogs removes logs older than maxAgeDays
func (l *Logger) cleanupOldLogs() {
	if !l.enabled || l.maxAgeDays <= 0 {
		return
	}

	logDir := filepath.Dir(l.logPath)
	baseName := filepath.Base(l.logPath)
	cutoffTime := time.Now().AddDate(0, 0, -l.maxAgeDays)

	files, err := filepath.Glob(filepath.Join(logDir, baseName+".*"))
	if err != nil {
		return
	}

	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			continue
		}

		if fileInfo.ModTime().Before(cutoffTime) {
			os.Remove(file)
			log.Printf("Cleaned up old log: %s", file)
		}
	}
}

// Close closes the log file and flushes remaining events
func (l *Logger) Close() error {
	if !l.enabled || l.file == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.flushTimer != nil {
		l.flushTimer.Stop()
	}
	if l.rotationTimer != nil {
		l.rotationTimer.Stop()
	}

	l.flushBuffer()

	closeEvent := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"event":         "logger_closed",
		"events_logged": l.eventCount,
	}
	l.jsonEncoder.Encode(closeEvent)
	l.bufWriter.Flush()

	if l.humanEnabled && l.humanWriter != nil {
		l.humanWriter.WriteString(l.formatHumanLine(closeEvent) + "\n")
		l.humanWriter.Flush()
	}

	if l.humanFile != nil {
		l.humanFile.Close()
	}

	return l.file.Close()
}

// Flush ensures all buffered data is written to disk
func (l *Logger) Flush() error {
	if !l.enabled {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.flushBuffer()
	return nil
}

// GetLogPath returns the current log file path
func (l *Logger) GetLogPath() string {
	return l.logPath
}

// GetEventCount returns the total number of events logged
func (l *Logger) GetEventCount() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.eventCount
}

// determineAction suggests an action based on attack severity
func determineAction(entry *IPEntry, excessPercent int) string {
	if entry.ViolationCount > 10 {
		return "PERMANENT_BAN - Persistent attacker, consider firewall-level block"
	}
	if excessPercent > 500 {
		return "EXTENDED_BLOCK - Severe violation, extend block to 1+ hours"
	}
	if excessPercent > 200 {
		return "MONITOR_CLOSELY - High excess rate, watch for escalation"
	}
	if entry.ViolationCount > 5 {
		return "REPUTATION_WATCH - Multiple violations, likely malicious"
	}
	return "STANDARD_BLOCK - Temporary block, monitor for repeat offense"
}

// formatHumanLine converts an event (struct or map) to a concise human-readable line
func (l *Logger) formatHumanLine(v interface{}) string {
	switch ev := v.(type) {
	case DDoSEvent:
		// Base line
		sev := strings.ToUpper(ev.Severity)
		parts := []string{fmt.Sprintf("[%s] [%s] %s", ev.Timestamp, sev, ev.EventType)}
		if ev.IP != "" {
			parts = append(parts, fmt.Sprintf("ip=%s", ev.IP))
		}
		if ev.RateLimit > 0 && ev.ActualRate > 0 {
			parts = append(parts, fmt.Sprintf("rate=%d/%d", ev.ActualRate, ev.RateLimit))
		}
		if ev.ExcessPercentage != 0 {
			parts = append(parts, fmt.Sprintf("excess=%d%%", ev.ExcessPercentage))
		}
		if ev.ActiveConnections > 0 {
			parts = append(parts, fmt.Sprintf("conns=%d", ev.ActiveConnections))
		}
		if ev.ThrottleLevel > 0 {
			parts = append(parts, fmt.Sprintf("throttle=L%d", ev.ThrottleLevel))
		}
		if ev.Message != "" {
			parts = append(parts, fmt.Sprintf("msg=\"%s\"", ev.Message))
		}
		return strings.Join(parts, " ")
	case map[string]interface{}:
		// Known admin events
		if evt, ok := ev["event"].(string); ok {
			ts, _ := ev["timestamp"].(string)
			switch evt {
			case "logger_initialized":
				lp, _ := ev["log_path"].(string)
				hr, _ := ev["human_readable"].(bool)
				hp, _ := ev["human_path"].(string)
				return fmt.Sprintf("[%s] [INFO] logger_initialized json=%s human=%t human_path=%s", ts, lp, hr, hp)
			case "log_rotation":
				nf, _ := ev["new_file"].(string)
				return fmt.Sprintf("[%s] [INFO] log_rotation new_file=%s", ts, nf)
			case "log_rotated":
				from, _ := ev["from"].(string)
				return fmt.Sprintf("[%s] [INFO] log_rotated from=%s", ts, from)
			case "logger_closed":
				cnt := ev["events_logged"]
				return fmt.Sprintf("[%s] [INFO] logger_closed events=%v", ts, cnt)
			}
		}
		// Fallback generic map
		b, _ := json.Marshal(ev)
		return string(b)
	default:
		// Unknown type
		return fmt.Sprintf("%v", v)
	}
}
