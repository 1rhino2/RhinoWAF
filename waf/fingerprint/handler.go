package fingerprint

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Middleware wraps HTTP handlers to collect and validate fingerprints
type Middleware struct {
	tracker *Tracker
}

func NewMiddleware(tracker *Tracker) *Middleware {
	return &Middleware{
		tracker: tracker,
	}
}

// Handler wraps an HTTP handler to track fingerprints
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.tracker.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip fingerprint collection endpoint itself
		if r.URL.Path == "/fingerprint/collect" {
			next.ServeHTTP(w, r)
			return
		}

		ip := getIP(r)

		// Extract server-side fingerprint
		fp := m.tracker.ExtractFromRequest(r)

		// Check if we have client-side data in cookie
		if cookie, err := r.Cookie("waf_fingerprint"); err == nil && cookie.Value != "" {
			// Already have fingerprint, validate it
			fp.Hash = cookie.Value
			allowed, reason := m.tracker.Check(ip, fp)
			if !allowed {
				http.Error(w, fmt.Sprintf("Access blocked: %s", reason), http.StatusForbidden)
				return
			}

			// Track this visit
			_ = m.tracker.Track(ip, fp)
			next.ServeHTTP(w, r)
			return
		}

		// No fingerprint cookie - inject collection script
		if acceptsHTML(r) {
			m.serveCollectionPage(w, r)
			return
		}

		// Non-HTML request without fingerprint (API, JSON, etc.)
		if m.tracker.config.RequireClientData {
			http.Error(w, "Browser verification is required to access this resource", http.StatusForbidden)
			return
		}

		// Allow through but track server-side fingerprint only
		fp.Hash = m.tracker.generateHash(fp)
		_ = m.tracker.Track(ip, fp)
		next.ServeHTTP(w, r)
	})
}

// CollectHandler receives fingerprint data from client-side JS
func (m *Middleware) CollectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "This endpoint only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	ip := getIP(r)

	// Apply rate limiting to prevent fingerprint collection DoS
	if !m.tracker.rateLimiter.Allow(ip, m.tracker.config.CollectionRateLimit, 1*time.Minute) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "blocked",
			"reason": "Rate limit exceeded. Please wait a moment and try again.",
		})
		return
	}

	var data FingerprintData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Unable to process fingerprint data. Please refresh the page.", http.StatusBadRequest)
		return
	}

	// Extract server-side components
	fp := m.tracker.ExtractFromRequest(r)

	// Merge client-side data
	m.tracker.MergeClientData(fp, &data)

	// Validate fingerprint
	allowed, reason := m.tracker.Check(ip, fp)
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "blocked",
			"reason": reason,
		})
		return
	}

	// Track fingerprint
	if err := m.tracker.Track(ip, fp); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "blocked",
			"reason": err.Error(),
		})
		return
	}

	// Set fingerprint cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "waf_fingerprint",
		Value:    fp.Hash,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"fingerprint": fp.Hash[:8], // Return truncated hash
	})
}

// serveCollectionPage serves HTML with fingerprint collection JavaScript
func (m *Middleware) serveCollectionPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Security Verification</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 400px;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        h2 { color: #333; margin-top: 0; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Security Verification</h2>
        <div class="spinner"></div>
        <p>Please wait while we verify your browser security...</p>
        <p style="font-size: 12px; color: #999;">This will only take a moment</p>
    </div>

    <script>
    (function() {
        // Collect comprehensive browser fingerprint
        const fingerprint = {
            screen_width: screen.width,
            screen_height: screen.height,
            color_depth: screen.colorDepth,
            timezone_offset: new Date().getTimezoneOffset(),
            platform: navigator.platform,
            cpu_cores: navigator.hardwareConcurrency || 0,
            device_memory: navigator.deviceMemory || 0,
            do_not_track: navigator.doNotTrack || '',
            plugins: [],
            fonts: [],
            canvas: '',
            webgl: ''
        };

        // Collect plugins
        for (let i = 0; i < navigator.plugins.length; i++) {
            fingerprint.plugins.push(navigator.plugins[i].name);
        }

        // Canvas fingerprinting
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 200;
            canvas.height = 50;
            
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('RhinoWAF 🦏', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Fingerprint Test', 4, 17);
            
            fingerprint.canvas = canvas.toDataURL().slice(-50); // Last 50 chars
        } catch (e) {
            fingerprint.canvas = 'error';
        }

        // WebGL fingerprinting
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                    const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    fingerprint.webgl = (vendor + '|' + renderer).slice(0, 100);
                } else {
                    fingerprint.webgl = 'no_debug_info';
                }
            } else {
                fingerprint.webgl = 'not_supported';
            }
        } catch (e) {
            fingerprint.webgl = 'error';
        }

        // Font detection (detect common fonts)
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
            'Arial', 'Verdana', 'Times New Roman', 'Courier New',
            'Georgia', 'Palatino', 'Garamond', 'Bookman',
            'Comic Sans MS', 'Trebuchet MS', 'Impact'
        ];
        
        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        const baseFontWidths = {};
        baseFonts.forEach(baseFont => {
            ctx.font = testSize + ' ' + baseFont;
            baseFontWidths[baseFont] = ctx.measureText(testString).width;
        });
        
        testFonts.forEach(font => {
            let detected = false;
            baseFonts.forEach(baseFont => {
                ctx.font = testSize + ' ' + font + ',' + baseFont;
                const width = ctx.measureText(testString).width;
                if (width !== baseFontWidths[baseFont]) {
                    detected = true;
                }
            });
            if (detected) {
                fingerprint.fonts.push(font);
            }
        });

        // Send fingerprint to server
        fetch('/fingerprint/collect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(fingerprint)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Redirect to original URL
                window.location.href = window.location.pathname + window.location.search;
            } else {
                document.querySelector('.container').innerHTML = 
                    '<h2>Access Blocked</h2><p>' + (data.reason || 'Unable to verify browser') + '</p>';
            }
        })
        .catch(err => {
            document.querySelector('.container').innerHTML = 
                '<h2>Verification Error</h2><p>Could not complete verification. Please refresh the page and try again.</p>';
        });
    })();
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// StatsHandler returns fingerprint statistics
func (m *Middleware) StatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := m.tracker.GetStats()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func getIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}
