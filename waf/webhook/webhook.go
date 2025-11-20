package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Config holds webhook configuration
type Config struct {
	Enabled       bool     `json:"enabled"`
	URLs          []string `json:"urls"`            // Webhook URLs
	MinSeverity   string   `json:"min_severity"`    // Minimum severity to notify: info, warning, critical, emergency
	IncludeIPInfo bool     `json:"include_ip_info"` // Include detailed IP info in payload
	Timeout       int      `json:"timeout"`         // HTTP timeout in seconds (default: 5)
	MaxRetries    int      `json:"max_retries"`     // Max retry attempts (default: 2)
	SlackFormat   bool     `json:"slack_format"`    // Use Slack-specific formatting
	DiscordFormat bool     `json:"discord_format"`  // Use Discord-specific formatting
	TeamsFormat   bool     `json:"teams_format"`    // Use Microsoft Teams formatting
}

// Notifier handles webhook notifications
type Notifier struct {
	config Config
	client *http.Client
}

// AttackEvent represents an attack notification
type AttackEvent struct {
	Timestamp    string `json:"timestamp"`
	EventType    string `json:"event_type"` // "rate_limit", "burst", "malicious", "geo_block", "reputation"
	Severity     string `json:"severity"`   // "info", "warning", "critical", "emergency"
	IP           string `json:"ip"`
	Country      string `json:"country,omitempty"`
	Message      string `json:"message"`
	Details      string `json:"details,omitempty"`
	RequestCount int    `json:"request_count,omitempty"`
	Reputation   int    `json:"reputation,omitempty"`
	Action       string `json:"action"` // "blocked", "challenged", "rate_limited"
}

// NewNotifier creates a new webhook notifier
func NewNotifier(config Config) *Notifier {
	if config.Timeout == 0 {
		config.Timeout = 5
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 2
	}

	return &Notifier{
		config: config,
		client: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}
}

// Notify sends a webhook notification for an attack event
func (n *Notifier) Notify(event AttackEvent) {
	if !n.config.Enabled {
		return
	}

	// Check severity threshold
	if !n.shouldNotify(event.Severity) {
		return
	}

	// Send to all configured webhooks
	for _, url := range n.config.URLs {
		go n.sendWebhook(url, event)
	}
}

func (n *Notifier) shouldNotify(severity string) bool {
	severityLevels := map[string]int{
		"info":      1,
		"warning":   2,
		"critical":  3,
		"emergency": 4,
	}

	minLevel := severityLevels[n.config.MinSeverity]
	eventLevel := severityLevels[severity]

	return eventLevel >= minLevel
}

func (n *Notifier) sendWebhook(url string, event AttackEvent) {
	var payload interface{}

	// Format payload based on webhook type
	if n.config.SlackFormat {
		payload = n.formatSlack(event)
	} else if n.config.DiscordFormat {
		payload = n.formatDiscord(event)
	} else if n.config.TeamsFormat {
		payload = n.formatTeams(event)
	} else {
		payload = event // Generic JSON
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Webhook: Failed to marshal payload: %v", err)
		return
	}

	// Retry logic
	for attempt := 0; attempt <= n.config.MaxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Webhook: Failed to create request: %v", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "RhinoWAF/2.3.1")

		resp, err := n.client.Do(req)
		if err != nil {
			if attempt < n.config.MaxRetries {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			log.Printf("Webhook: Failed to send notification: %v", err)
			return
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return // Success
		}

		if attempt < n.config.MaxRetries {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		} else {
			log.Printf("Webhook: Failed after %d attempts, status: %d", n.config.MaxRetries+1, resp.StatusCode)
		}
	}
}

func (n *Notifier) formatSlack(event AttackEvent) map[string]interface{} {
	color := "warning"
	switch event.Severity {
	case "critical", "emergency":
		color = "danger"
	case "info":
		color = "good"
	}

	emoji := ":shield:"
	switch event.EventType {
	case "rate_limit":
		emoji = ":hourglass:"
	case "burst":
		emoji = ":zap:"
	case "malicious":
		emoji = ":stop_sign:"
	case "geo_block":
		emoji = ":earth_americas:"
	}

	return map[string]interface{}{
		"text": fmt.Sprintf("%s *RhinoWAF Alert*", emoji),
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"fields": []map[string]interface{}{
					{"title": "Event Type", "value": event.EventType, "short": true},
					{"title": "Severity", "value": event.Severity, "short": true},
					{"title": "IP Address", "value": event.IP, "short": true},
					{"title": "Action", "value": event.Action, "short": true},
					{"title": "Message", "value": event.Message, "short": false},
				},
				"footer": "RhinoWAF v2.3.1",
				"ts":     time.Now().Unix(),
			},
		},
	}
}

func (n *Notifier) formatDiscord(event AttackEvent) map[string]interface{} {
	color := 16776960 // Yellow
	switch event.Severity {
	case "critical", "emergency":
		color = 16711680 // Red
	case "info":
		color = 65280 // Green
	}

	return map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "🛡️ RhinoWAF Security Alert",
				"description": event.Message,
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "Event Type", "value": event.EventType, "inline": true},
					{"name": "Severity", "value": event.Severity, "inline": true},
					{"name": "IP Address", "value": event.IP, "inline": true},
					{"name": "Action", "value": event.Action, "inline": true},
				},
				"footer": map[string]string{
					"text": "RhinoWAF v2.3.1",
				},
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}
}

func (n *Notifier) formatTeams(event AttackEvent) map[string]interface{} {
	themeColor := "FF6B6B" // Red
	switch event.Severity {
	case "warning":
		themeColor = "FFD93D" // Yellow
	case "info":
		themeColor = "6BCF7F" // Green
	}

	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    "RhinoWAF Security Alert",
		"themeColor": themeColor,
		"title":      "🛡️ RhinoWAF Security Alert",
		"sections": []map[string]interface{}{
			{
				"facts": []map[string]string{
					{"name": "Event Type", "value": event.EventType},
					{"name": "Severity", "value": event.Severity},
					{"name": "IP Address", "value": event.IP},
					{"name": "Action", "value": event.Action},
					{"name": "Message", "value": event.Message},
				},
			},
		},
	}
}

// Global notifier instance
var globalNotifier *Notifier

// Init initializes the global webhook notifier
func Init(config Config) {
	globalNotifier = NewNotifier(config)
	if config.Enabled {
		log.Printf("Webhook notifications enabled: %d URLs configured", len(config.URLs))
	}
}

// Send sends a notification using the global notifier
func Send(event AttackEvent) {
	if globalNotifier != nil {
		globalNotifier.Notify(event)
	}
}
