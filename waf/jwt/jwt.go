package jwt

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Enabled        bool
	Secret         string
	Algorithm      string
	ProtectedPaths []string
	RequiredClaims []string
	Issuer         string
	Audience       string
	SkipPaths      []string
}

type Handler struct {
	config Config
	method jwt.SigningMethod
}

type Claims struct {
	jwt.RegisteredClaims
	Custom map[string]interface{} `json:"custom,omitempty"`
}

func NewHandler(config Config) (*Handler, error) {
	if config.Secret == "" {
		return nil, errors.New("jwt secret is required")
	}

	if config.Algorithm == "" {
		config.Algorithm = "HS256"
	}

	var method jwt.SigningMethod
	switch config.Algorithm {
	case "HS256":
		method = jwt.SigningMethodHS256
	case "HS384":
		method = jwt.SigningMethodHS384
	case "HS512":
		method = jwt.SigningMethodHS512
	case "RS256":
		method = jwt.SigningMethodRS256
	case "RS384":
		method = jwt.SigningMethodRS384
	case "RS512":
		method = jwt.SigningMethodRS512
	default:
		return nil, errors.New("unsupported algorithm: " + config.Algorithm)
	}

	return &Handler{
		config: config,
		method: method,
	}, nil
}

func (h *Handler) Validate(r *http.Request) (bool, string) {
	if !h.config.Enabled {
		return true, ""
	}

	if h.shouldSkip(r.URL.Path) {
		return true, ""
	}

	if !h.isProtectedPath(r.URL.Path) {
		return true, ""
	}

	tokenString := h.extractToken(r)
	if tokenString == "" {
		return false, "missing JWT token"
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != h.method {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(h.config.Secret), nil
	})

	if err != nil {
		return false, "invalid token: " + err.Error()
	}

	if !token.Valid {
		return false, "token validation failed"
	}

	if h.config.Issuer != "" && claims.Issuer != h.config.Issuer {
		return false, "invalid issuer"
	}

	if h.config.Audience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == h.config.Audience {
				found = true
				break
			}
		}
		if !found {
			return false, "invalid audience"
		}
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return false, "token expired"
	}

	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return false, "token not yet valid"
	}

	for _, required := range h.config.RequiredClaims {
		if claims.Custom[required] == nil {
			return false, "missing required claim: " + required
		}
	}

	return true, ""
}

func (h *Handler) extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		cookie, err := r.Cookie("jwt")
		if err == nil {
			return cookie.Value
		}
		return ""
	}

	parts := strings.Split(auth, " ")
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}

	return ""
}

func (h *Handler) isProtectedPath(path string) bool {
	if len(h.config.ProtectedPaths) == 0 {
		return true
	}

	for _, protected := range h.config.ProtectedPaths {
		if strings.HasPrefix(path, protected) {
			return true
		}
	}

	return false
}

func (h *Handler) shouldSkip(path string) bool {
	for _, skip := range h.config.SkipPaths {
		if strings.HasPrefix(path, skip) {
			return true
		}
	}
	return false
}

func (h *Handler) GenerateToken(claims *Claims) (string, error) {
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	}

	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}

	if h.config.Issuer != "" {
		claims.Issuer = h.config.Issuer
	}

	if h.config.Audience != "" {
		claims.Audience = []string{h.config.Audience}
	}

	token := jwt.NewWithClaims(h.method, claims)
	return token.SignedString([]byte(h.config.Secret))
}
