package templates

import (
	_ "embed"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

//go:embed error.html
var errorTemplate string

var tmpl *template.Template
var customTemplates map[int]*template.Template

func init() {
	var err error
	tmpl, err = template.New("error").Parse(errorTemplate)
	if err != nil {
		panic("Failed to parse error template: " + err.Error())
	}
	customTemplates = make(map[int]*template.Template)
}

// ErrorData contains data for error page rendering
type ErrorData struct {
	Icon       string
	Title      string
	StatusCode int
	Message    string
	Details    string
	Timestamp  string
}

func LoadCustomTemplate(statusCode int, templatePath string) error {
	absPath, err := filepath.Abs(templatePath)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(absPath)
	if err != nil {
		return err
	}

	t, err := template.New("custom").Parse(string(content))
	if err != nil {
		return err
	}

	customTemplates[statusCode] = t
	return nil
}

func getTemplate(statusCode int) *template.Template {
	if ct, exists := customTemplates[statusCode]; exists {
		return ct
	}
	return tmpl
}

// RenderError renders a custom error page
func RenderError(w http.ResponseWriter, statusCode int, title, message, details string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	icon := "🛡️"
	switch statusCode {
	case http.StatusTooManyRequests:
		icon = "⏱️"
	case http.StatusForbidden:
		icon = "🚫"
	case http.StatusUnauthorized:
		icon = "🔒"
	case http.StatusBadRequest:
		icon = "⚠️"
	case http.StatusServiceUnavailable:
		icon = "🔧"
	}

	data := ErrorData{
		Icon:       icon,
		Title:      title,
		StatusCode: statusCode,
		Message:    message,
		Details:    details,
		Timestamp:  time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	activeTemplate := getTemplate(statusCode)
	if err := activeTemplate.Execute(w, data); err != nil {
		// Fallback to plain text if template fails
		http.Error(w, message, statusCode)
	}
}

// RenderRateLimitError renders a rate limit error page
func RenderRateLimitError(w http.ResponseWriter, ip string) {
	RenderError(w, http.StatusTooManyRequests,
		"Rate Limit Exceeded",
		"You have exceeded the maximum number of requests allowed.",
		"Your IP address ("+ip+") has been temporarily rate limited. Please try again later.")
}

// RenderBlockedError renders a blocked IP error page
func RenderBlockedError(w http.ResponseWriter, ip, reason string) {
	RenderError(w, http.StatusForbidden,
		"Access Denied",
		"Your request has been blocked by our security system.",
		"IP: "+ip+"\nReason: "+reason)
}

// RenderMaliciousError renders a malicious input error page
func RenderMaliciousError(w http.ResponseWriter) {
	RenderError(w, http.StatusForbidden,
		"Malicious Input Detected",
		"Your request contains patterns that match known attack signatures.",
		"Please review your input and try again. If you believe this is an error, contact support.")
}

// RenderChallengeError renders a challenge required error page
func RenderChallengeError(w http.ResponseWriter) {
	RenderError(w, http.StatusForbidden,
		"Security Challenge Required",
		"Please complete the security challenge to continue.",
		"This helps us protect our service from automated attacks.")
}
