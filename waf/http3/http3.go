package http3

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Config struct {
	Enabled      bool     `json:"enabled"`
	Port         string   `json:"port"`
	CertFile     string   `json:"cert_file"`
	KeyFile      string   `json:"key_file"`
	MaxStreams   int64    `json:"max_streams"`
	IdleTimeout  int      `json:"idle_timeout"`
	AltSvcHeader bool     `json:"alt_svc_header"`
	Domains      []string `json:"domains"`
}

type Server struct {
	config     Config
	server     *http3.Server
	quicConfig *quic.Config
	mu         sync.RWMutex
	running    bool
}

func NewServer(cfg Config) *Server {
	if cfg.Port == "" {
		cfg.Port = ":443"
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = 100
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30
	}

	quicCfg := &quic.Config{
		MaxIncomingStreams:    cfg.MaxStreams,
		MaxIdleTimeout:        time.Duration(cfg.IdleTimeout) * time.Second,
		KeepAlivePeriod:       time.Second * 15,
		EnableDatagrams:       false,
		MaxIncomingUniStreams: 10,
	}

	return &Server{
		config:     cfg,
		quicConfig: quicCfg,
		running:    false,
	}
}

func (s *Server) Start(handler http.Handler) error {
	if !s.config.Enabled {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3", "h3-29"},
	}

	wrappedHandler := s.wrapHandler(handler)

	s.server = &http3.Server{
		Addr:       s.config.Port,
		Handler:    wrappedHandler,
		TLSConfig:  tlsConfig,
		QUICConfig: s.quicConfig,
	}

	s.running = true

	go func() {
		log.Printf("[HTTP/3] Starting server on %s", s.config.Port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP/3] Server error: %v", err)
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}
	}()

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.server == nil {
		return nil
	}

	log.Println("[HTTP/3] Shutting down server")
	err := s.server.Close()
	s.running = false
	return err
}

func (s *Server) wrapHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.AltSvcHeader {
			s.addAltSvcHeader(w, r)
		}
		handler.ServeHTTP(w, r)
	})
}

func (s *Server) addAltSvcHeader(w http.ResponseWriter, r *http.Request) {
	if len(s.config.Domains) == 0 {
		port := s.config.Port
		if port[0] == ':' {
			port = port[1:]
		}
		w.Header().Set("Alt-Svc", `h3=":443"; ma=2592000`)
		return
	}

	for _, domain := range s.config.Domains {
		if r.Host == domain || r.Host == domain+s.config.Port {
			port := s.config.Port
			if port[0] == ':' {
				port = port[1:]
			}
			w.Header().Set("Alt-Svc", `h3=":443"; ma=2592000`)
			return
		}
	}
}

func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func AltSvcMiddleware(port string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if port == "" {
				port = "443"
			}
			w.Header().Set("Alt-Svc", `h3=":443"; ma=2592000`)
			next.ServeHTTP(w, r)
		})
	}
}
