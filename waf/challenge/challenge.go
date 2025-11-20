package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ChallengeType string

const (
	TypeJavaScript  ChallengeType = "javascript"
	TypeProofOfWork ChallengeType = "proof_of_work"
	TypeHCaptcha    ChallengeType = "hcaptcha"
	TypeTurnstile   ChallengeType = "turnstile"
)

type Session struct {
	Token         string
	IP            string
	ChallengeType ChallengeType
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Verified      bool
	Challenge     string // POW challenge string
	Difficulty    int
}

type Manager struct {
	sessions        map[string]*Session
	mu              sync.RWMutex
	hcaptchaKey     string
	hcaptchaSecret  string
	turnstileKey    string
	turnstileSecret string
	sessionTTL      time.Duration
}

func NewManager() *Manager {
	m := &Manager{
		sessions:   make(map[string]*Session),
		sessionTTL: 15 * time.Minute,
	}
	go m.cleanupExpired()
	return m
}

func (m *Manager) SetHCaptcha(siteKey, secret string) {
	m.hcaptchaKey = siteKey
	m.hcaptchaSecret = secret
}

func (m *Manager) SetTurnstile(siteKey, secret string) {
	m.turnstileKey = siteKey
	m.turnstileSecret = secret
}

func (m *Manager) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for token, session := range m.sessions {
			if now.After(session.ExpiresAt) {
				delete(m.sessions, token)
			}
		}
		m.mu.Unlock()
	}
}

func (m *Manager) generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) CreateSession(ip string, challengeType ChallengeType, difficulty int) *Session {
	token := m.generateToken()
	challenge := ""

	if challengeType == TypeProofOfWork {
		challenge = m.generatePOWChallenge(difficulty)
	}

	session := &Session{
		Token:         token,
		IP:            ip,
		ChallengeType: challengeType,
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(m.sessionTTL),
		Verified:      false,
		Challenge:     challenge,
		Difficulty:    difficulty,
	}

	m.mu.Lock()
	m.sessions[token] = session
	m.mu.Unlock()

	return session
}

func (m *Manager) GetSession(token string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// constant-time comparison to prevent timing attacks
	for storedToken, session := range m.sessions {
		if subtle.ConstantTimeCompare([]byte(storedToken), []byte(token)) == 1 {
			if time.Now().After(session.ExpiresAt) {
				return nil, false
			}
			return session, true
		}
	}
	return nil, false
}

func (m *Manager) VerifySession(token string) bool {
	m.mu.RLock()
	session, exists := m.sessions[token]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		return false
	}

	return session.Verified
}

func (m *Manager) MarkVerified(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, exists := m.sessions[token]; exists {
		session.Verified = true
		session.ExpiresAt = time.Now().Add(1 * time.Hour)
	}
}

func (m *Manager) generatePOWChallenge(difficulty int) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) VerifyPOW(challenge, solution string, difficulty int) bool {
	data := challenge + solution
	hash := sha256.Sum256([]byte(data))
	hashStr := hex.EncodeToString(hash[:])

	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hashStr, prefix)
}

func (m *Manager) VerifyHCaptcha(response, remoteIP string) (bool, error) {
	if m.hcaptchaSecret == "" {
		return false, fmt.Errorf("hCaptcha verification is not configured on this server")
	}

	payload := fmt.Sprintf("response=%s&secret=%s&remoteip=%s", response, m.hcaptchaSecret, remoteIP)
	resp, err := http.Post(
		"https://hcaptcha.com/siteverify",
		"application/x-www-form-urlencoded",
		strings.NewReader(payload),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Success, nil
}

func (m *Manager) VerifyTurnstile(response, remoteIP string) (bool, error) {
	if m.turnstileSecret == "" {
		return false, fmt.Errorf("Cloudflare Turnstile verification is not configured on this server")
	}

	payload := fmt.Sprintf(`{"response":"%s","secret":"%s","remoteip":"%s"}`, response, m.turnstileSecret, remoteIP)
	resp, err := http.Post(
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		"application/json",
		strings.NewReader(payload),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Success, nil
}

func (m *Manager) RenderChallengePage(w http.ResponseWriter, session *Session) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	var html string
	switch session.ChallengeType {
	case TypeJavaScript:
		html = m.renderJSChallenge(session)
	case TypeProofOfWork:
		html = m.renderPOWChallenge(session)
	case TypeHCaptcha:
		html = m.renderHCaptchaChallenge(session)
	case TypeTurnstile:
		html = m.renderTurnstileChallenge(session)
	default:
		html = m.renderJSChallenge(session)
	}

	_, _ = w.Write([]byte(html))
}

func (m *Manager) renderJSChallenge(session *Session) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Check</title>
<style>
body { font-family: system-ui; max-width: 600px; margin: 80px auto; padding: 20px; background: #f5f5f5; }
.box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
h1 { margin: 0 0 20px; color: #333; }
p { color: #666; line-height: 1.6; }
.spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
@keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="box">
<h1>Security Verification</h1>
<p>We need to verify you're human. This will only take a moment...</p>
<div class="spinner"></div>
</div>
<script>
setTimeout(function() {
  fetch('/challenge/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: '%s', type: 'javascript' })
  }).then(function(r) {
    if (r.ok) {
      window.location.reload();
    }
  });
}, 2000);
</script>
</body>
</html>`, session.Token)
}

func (m *Manager) renderPOWChallenge(session *Session) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Check</title>
<style>
body { font-family: system-ui; max-width: 600px; margin: 80px auto; padding: 20px; background: #f5f5f5; }
.box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
h1 { margin: 0 0 20px; color: #333; }
p { color: #666; line-height: 1.6; }
.spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
@keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
#status { margin-top: 20px; color: #888; }
</style>
</head>
<body>
<div class="box">
<h1>Security Verification</h1>
<p>Please wait while we verify your browser security...</p>
<div class="spinner"></div>
<div id="status">Initializing verification...</div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script>
var challenge = '%s';
var difficulty = %d;
var nonce = 0;
var found = false;

function findSolution() {
  var start = Date.now();
  while (!found && nonce < 1000000) {
    var attempt = challenge + nonce;
    var hash = CryptoJS.SHA256(attempt).toString();
    var prefix = '0'.repeat(difficulty);
    
    if (hash.startsWith(prefix)) {
      found = true;
      document.getElementById('status').textContent = 'Solution found! Verifying...';
      
      fetch('/challenge/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          token: '%s',
          type: 'proof_of_work',
          solution: String(nonce)
        })
      }).then(function(r) {
        if (r.ok) {
          window.location.reload();
        } else {
          document.getElementById('status').textContent = 'Verification unsuccessful. Please refresh the page.';
        }
      });
      break;
    }
    
    nonce++;
    if (nonce %% 10000 === 0) {
      document.getElementById('status').textContent = 'Testing solution ' + nonce + '...';
      setTimeout(findSolution, 10);
      return;
    }
  }
  
  if (!found && nonce >= 1000000) {
    document.getElementById('status').textContent = 'Unable to complete verification. Please refresh the page.';
  }
}

setTimeout(findSolution, 100);
</script>
</body>
</html>`, session.Challenge, session.Difficulty, session.Token)
}

func (m *Manager) renderHCaptchaChallenge(session *Session) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Check</title>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<style>
body { font-family: system-ui; max-width: 600px; margin: 80px auto; padding: 20px; background: #f5f5f5; }
.box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
h1 { margin: 0 0 20px; color: #333; }
p { color: #666; line-height: 1.6; margin-bottom: 30px; }
.error { color: #d32f2f; background: #ffebee; padding: 12px; border-radius: 4px; margin: 20px 0; display: none; }
</style>
</head>
<body>
<div class="box">
<h1>Security Verification</h1>
<p>Please complete the verification below to continue:</p>
<div id="error-message" class="error"></div>
<form id="captcha-form">
<div class="h-captcha" data-sitekey="%s" data-callback="onCaptchaSuccess"></div>
<input type="hidden" name="token" value="%s">
</form>
</div>
<script>
function showError(msg) {
  var errorDiv = document.getElementById('error-message');
  errorDiv.textContent = msg;
  errorDiv.style.display = 'block';
}
function onCaptchaSuccess(response) {
  fetch('/challenge/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: '%s',
      type: 'hcaptcha',
      response: response
    })
  }).then(function(r) {
    return r.json().then(function(data) {
      if (r.ok && data.success) {
        window.location.reload();
      } else {
        showError(data.error || 'Verification failed. Please try again.');
        hcaptcha.reset();
      }
    });
  }).catch(function(err) {
    showError('Network error. Please check your connection and try again.');
  });
}
</script>
</body>
</html>`, m.hcaptchaKey, session.Token, session.Token)
}

func (m *Manager) renderTurnstileChallenge(session *Session) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Check</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
body { font-family: system-ui; max-width: 600px; margin: 80px auto; padding: 20px; background: #f5f5f5; }
.box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
h1 { margin: 0 0 20px; color: #333; }
p { color: #666; line-height: 1.6; margin-bottom: 30px; }
.error { color: #d32f2f; background: #ffebee; padding: 12px; border-radius: 4px; margin: 20px 0; display: none; }
</style>
</head>
<body>
<div class="box">
<h1>Security Verification</h1>
<p>Please complete the verification below to continue:</p>
<div id="error-message" class="error"></div>
<div class="cf-turnstile" data-sitekey="%s" data-callback="onTurnstileSuccess"></div>
<input type="hidden" id="token" value="%s">
</div>
<script>
function showError(msg) {
  var errorDiv = document.getElementById('error-message');
  errorDiv.textContent = msg;
  errorDiv.style.display = 'block';
}
function onTurnstileSuccess(response) {
  fetch('/challenge/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: document.getElementById('token').value,
      type: 'turnstile',
      response: response
    })
  }).then(function(r) {
    return r.json().then(function(data) {
      if (r.ok && data.success) {
        window.location.reload();
      } else {
        showError(data.error || 'Verification failed. Please try again.');
        turnstile.reset();
      }
    });
  }).catch(function(err) {
    showError('Network error. Please check your connection and try again.');
  });
}
</script>
</body>
</html>`, m.turnstileKey, session.Token)
}
