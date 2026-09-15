package engine

import (
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Event is one engine decision, logged as a json line and a human line.
type Event struct {
	Time      time.Time  `json:"ts"`
	RequestID string     `json:"request_id,omitempty"`
	IP        string     `json:"ip"`
	Host      string     `json:"host"`
	Method    string     `json:"method"`
	Path      string     `json:"path"`
	Action    string     `json:"action"`
	Mode      string     `json:"mode"`
	Score     int        `json:"score"`
	Threshold int        `json:"threshold"`
	Paranoia  int        `json:"paranoia"`
	TopLabel  string     `json:"top_label,omitempty"`
	Phase     string     `json:"phase"`
	Ruleset   string     `json:"ruleset"`
	Evidence  []Evidence `json:"evidence,omitempty"`
}

// EventSink receives engine events. Implementations must be concurrency safe.
type EventSink interface {
	Log(Event)
}

type nopSink struct{}

func (nopSink) Log(Event) {}

// FileSink writes json lines to a rotating file and a short human line to
// the standard logger.
type FileSink struct {
	w    *lumberjack.Logger
	ring *ring
}

// NewFileSink opens the engine log with rotation.
func NewFileSink(path string, maxSizeMB, maxAgeDays, maxBackups int, compress bool) *FileSink {
	return &FileSink{
		w: &lumberjack.Logger{
			Filename:   path,
			MaxSize:    nonZero(maxSizeMB, 100),
			MaxAge:     nonZero(maxAgeDays, 30),
			MaxBackups: nonZero(maxBackups, 3),
			Compress:   compress,
		},
		ring: newRing(1000),
	}
}

func (s *FileSink) Log(e Event) {
	s.ring.add(e)
	if b, err := json.Marshal(e); err == nil {
		b = append(b, '\n')
		_, _ = s.w.Write(b)
	}
	if e.Action == "block" || e.Action == "detect" {
		log.Printf("[ENGINE] %s %s %s %s score=%d/%d pl=%d top=%s rules=%s req=%s",
			upper(e.Action), e.IP, e.Method, e.Path, e.Score, e.Threshold, e.Paranoia, e.TopLabel, ruleIDs(e.Evidence), e.RequestID)
	}
}

// Recent returns the last decisions for the explain endpoint.
func (s *FileSink) Recent(n int) []Event { return s.ring.recent(n) }

func ruleIDs(ev []Evidence) string {
	out := ""
	for i, e := range ev {
		if i > 0 {
			out += ","
		}
		out += itoa(e.RuleID)
	}
	return out
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// ring is a small lock-guarded circular buffer of recent events.
type ring struct {
	mu   sync.Mutex
	buf  []Event
	next int
	size int
}

func newRing(n int) *ring { return &ring{buf: make([]Event, n)} }

func (r *ring) add(e Event) {
	r.mu.Lock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
	if r.size < len(r.buf) {
		r.size++
	}
	r.mu.Unlock()
}

func (r *ring) recent(n int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > r.size {
		n = r.size
	}
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		idx := (r.next - 1 - i + len(r.buf)) % len(r.buf)
		out = append(out, r.buf[idx])
	}
	return out
}

// stats counts matches for the /engine/stats endpoint.
type stats struct {
	total atomic.Uint64
}
