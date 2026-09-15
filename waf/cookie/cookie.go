// Package cookie signs and verifies the small set of cookies the WAF hands
// out (challenge passed, fingerprint collected). Before this the cookies
// were bare session ids looked up in a map, so a restart logged everyone
// out and anyone who guessed an id was in. Now the cookie carries its own
// claim and an HMAC, the server keeps nothing.
package cookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Signer holds the key. One per process, shared by every middleware.
type Signer struct {
	key []byte
}

// NewSigner rejects short keys, 32 random bytes is the intended size.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 16 {
		return nil, errors.New("cookie: key must be at least 16 bytes")
	}
	return &Signer{key: append([]byte(nil), key...)}, nil
}

// RandomKey is what we persist on first start when the operator set none.
func RandomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("cookie: crypto/rand failed: " + err.Error())
	}
	return k
}

var enc = base64.RawURLEncoding

// Sign builds `b64(payload).exp.b64(mac)`. payload is opaque to us but
// should not carry secrets, it is readable by the client.
func (s *Signer) Sign(payload string, ttl time.Duration) string {
	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	body := enc.EncodeToString([]byte(payload)) + "." + exp
	return body + "." + enc.EncodeToString(s.mac(body))
}

// Verify returns the payload when the mac matches and it has not expired.
func (s *Signer) Verify(value string) (string, bool) {
	// split from the right, the payload itself has no dots after base64
	i := strings.LastIndexByte(value, '.')
	if i <= 0 {
		return "", false
	}
	body, sig := value[:i], value[i+1:]
	want, err := enc.DecodeString(sig)
	if err != nil || subtle.ConstantTimeCompare(want, s.mac(body)) != 1 {
		return "", false
	}
	j := strings.LastIndexByte(body, '.')
	if j <= 0 {
		return "", false
	}
	exp, err := strconv.ParseInt(body[j+1:], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	p, err := enc.DecodeString(body[:j])
	if err != nil {
		return "", false
	}
	return string(p), true
}

func (s *Signer) mac(body string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(body))
	return m.Sum(nil)
}

// Set writes a signed cookie. Secure follows the connection so plain http
// dev setups still work, and Lax lets top-level navigations carry it.
func (s *Signer) Set(w http.ResponseWriter, r *http.Request, name, payload string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    s.Sign(payload, ttl),
		Path:     "/",
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
	})
}

// Get reads and verifies a cookie in one go.
func (s *Signer) Get(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", false
	}
	return s.Verify(c.Value)
}

// IPClass is what we bind a pass to: /24 for v4, /64 for v6. Tight enough
// that a token cannot be shared across networks, loose enough that a phone
// hopping between carrier addresses is not re-challenged every minute.
func IPClass(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
