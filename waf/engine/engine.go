// Package engine is RhinoWAF's detection engine: a rule set written in a
// small text DSL, evaluated with anomaly scoring, per-argument so one long
// legit value cannot stack notices into a block. Rules decode their input
// through an explicit transform chain and match with real detectors
// (a sql tokenizer, an html-aware xss check) rather than substring greps,
// so it catches the evasions and skips the false positives the old
// sanitize heuristics tripped on. Every block carries evidence: which rule,
// which target, the matched bytes.
package engine

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rhinowaf/waf/engine/body"
)

// Config is the engine section of features.json. Every field is wired.
type Config struct {
	Enabled           bool           `json:"enabled"`
	Mode              string         `json:"mode"`     // block | detect
	Paranoia          int            `json:"paranoia"` // 1-4
	InboundThreshold  int            `json:"inbound_threshold"`
	OutboundThreshold int            `json:"outbound_threshold"`
	ScoringMode       string         `json:"scoring_mode"` // per_arg | sum
	RulesDir          string         `json:"rules_dir"`
	ExtraRulesDir     string         `json:"extra_rules_dir"`
	AllowedMethods    []string       `json:"allowed_methods"`
	AllowedTypes      []string       `json:"allowed_content_types"`
	Limits            LimitsConfig   `json:"limits"`
	BodyOverLimit     string         `json:"body_over_limit"`  // inspect_prefix | skip | block
	ExplainOnBlock    string         `json:"explain_on_block"` // none | rules | full
	LogAllowed        bool           `json:"log_allowed"`
	Response          ResponseConfig `json:"response"`
	Paths             []PathOverride `json:"paths"`
}

type LimitsConfig struct {
	MaxBodyInspectBytes int64 `json:"max_body_inspect_bytes"`
	MaxArgs             int   `json:"max_args"`
	MaxArgLength        int   `json:"max_arg_length"`
	MaxJSONDepth        int   `json:"max_json_depth"`
	MaxJSONLeaves       int   `json:"max_json_leaves"`
	MaxMultipartParts   int   `json:"max_multipart_parts"`
	MaxFileHeadBytes    int   `json:"max_file_head_bytes"`
	MaxTransformBytes   int   `json:"max_transform_bytes"`
}

type ResponseConfig struct {
	Mode           string `json:"mode"`           // off | detect | block
	InspectStatus  string `json:"inspect_status"` // 5xx | 4xx+ | all
	MaxBytes       int    `json:"max_bytes"`
	DecompressGzip bool   `json:"decompress_gzip"`
}

// PathOverride tunes the engine for a path prefix or glob.
type PathOverride struct {
	Prefix        string            `json:"prefix"`
	Glob          string            `json:"glob"`
	Mode          string            `json:"mode"`
	Paranoia      int               `json:"paranoia"`
	Threshold     int               `json:"threshold"`
	DisabledRules []int             `json:"disabled_rules"`
	Exclusions    []ExclusionConfig `json:"exclusions"`
}

// SiteOverride is the per-vhost engine block from backends.json.
type SiteOverride struct {
	Mode          string            `json:"mode"`
	Paranoia      int               `json:"paranoia"`
	Threshold     int               `json:"threshold"`
	DisabledRules []int             `json:"disabled_rules"`
	DetectRules   []int             `json:"detect_rules"`
	Exclusions    []ExclusionConfig `json:"exclusions"`
	Paths         []PathOverride    `json:"paths"`
}

type ExclusionConfig struct {
	Rules   []int    `json:"rules"`
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
	Targets []string `json:"targets"`
}

// DefaultConfig is what a missing engine section behaves like.
func DefaultConfig() Config {
	return Config{
		Enabled: true, Mode: "block", Paranoia: 1,
		InboundThreshold: 5, OutboundThreshold: 4, ScoringMode: "per_arg",
		ExtraRulesDir:  "rules.d",
		AllowedMethods: []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedTypes:   []string{"application/x-www-form-urlencoded", "multipart/form-data", "application/json", "application/xml", "text/xml", "text/plain"},
		Limits: LimitsConfig{
			MaxBodyInspectBytes: 262144, MaxArgs: 500, MaxArgLength: 65536,
			MaxJSONDepth: 32, MaxJSONLeaves: 5000, MaxMultipartParts: 100,
			MaxFileHeadBytes: 0, MaxTransformBytes: 262144,
		},
		BodyOverLimit: "inspect_prefix", ExplainOnBlock: "rules",
		Response: ResponseConfig{Mode: "detect", InspectStatus: "5xx", MaxBytes: 16384, DecompressGzip: true},
	}
}

// Validate checks the config independent of the ruleset.
func (c Config) Validate() error {
	switch c.Mode {
	case "", "block", "detect":
	default:
		return errf("engine.mode %q not block or detect", c.Mode)
	}
	if c.Paranoia < 1 || c.Paranoia > 4 {
		return errf("engine.paranoia %d out of range 1-4", c.Paranoia)
	}
	if c.InboundThreshold < 1 {
		return errf("engine.inbound_threshold must be >= 1")
	}
	if c.Limits.MaxBodyInspectBytes > 16<<20 {
		return errf("engine.limits.max_body_inspect_bytes over 16MiB")
	}
	switch c.BodyOverLimit {
	case "", "inspect_prefix", "skip", "block":
	default:
		return errf("engine.body_over_limit %q invalid", c.BodyOverLimit)
	}
	switch c.Response.Mode {
	case "", "off", "detect", "block":
	default:
		return errf("engine.response.mode %q invalid", c.Response.Mode)
	}
	return nil
}

// Engine is the live, swappable rule engine. One per process via Default().
type Engine struct {
	cfg    Config
	cur    atomic.Pointer[Ruleset]
	sites  atomic.Pointer[map[string]*SiteOverride]
	sink   atomic.Pointer[sinkHolder]
	loader atomic.Pointer[Loader]
	txPool sync.Pool
	stats  stats
}

type sinkHolder struct{ s EventSink }

var defaultEngine atomic.Pointer[Engine]

// Default is the process engine. Nil-safe: Inspect on a nil engine allows.
func Default() *Engine { return defaultEngine.Load() }

// SetDefault installs e as the process engine.
func SetDefault(e *Engine) { defaultEngine.Store(e) }

// New builds an engine from config and an already-compiled ruleset.
func New(cfg Config, rs *Ruleset) *Engine {
	e := &Engine{cfg: cfg}
	e.cur.Store(rs)
	e.txPool.New = func() any { return newTx() }
	e.setSink(nopSink{})
	sites := map[string]*SiteOverride{}
	e.sites.Store(&sites)
	return e
}

func (e *Engine) setSink(s EventSink) { e.sink.Store(&sinkHolder{s: s}) }

// SetSink swaps the event sink (log destination).
func (e *Engine) SetSink(s EventSink) { e.setSink(s) }

// SetSites installs per-vhost overrides (called on load and reload).
func (e *Engine) SetSites(m map[string]*SiteOverride) { e.sites.Store(&m) }

// Ruleset returns the current compiled set, for stats.
func (e *Engine) Ruleset() *Ruleset {
	if e == nil {
		return nil
	}
	return e.cur.Load()
}

// Config returns a copy of the engine config.
func (e *Engine) Cfg() Config { return e.cfg }

func (e *Engine) limits() body.Limits {
	l := e.cfg.Limits
	return body.Limits{
		MaxInspect:    nonZero64(l.MaxBodyInspectBytes, 262144),
		MaxArgs:       nonZero(l.MaxArgs, 500),
		MaxArgLen:     nonZero(l.MaxArgLength, 65536),
		MaxJSONDepth:  nonZero(l.MaxJSONDepth, 32),
		MaxJSONLeaves: nonZero(l.MaxJSONLeaves, 5000),
		MaxParts:      nonZero(l.MaxMultipartParts, 100),
		MaxFileHead:   l.MaxFileHeadBytes,
	}
}

// resolve builds the effective policy for a request. Precedence: global ->
// global paths -> site -> site paths.
func (e *Engine) resolve(host, reqPath, method string) *policy {
	pol := &policy{
		mode:          modeOf(e.cfg.Mode),
		paranoia:      uint8(clampPL(e.cfg.Paranoia)),
		threshold:     nonZero(e.cfg.InboundThreshold, 5),
		respThreshold: nonZero(e.cfg.OutboundThreshold, 4),
		scoringSum:    e.cfg.ScoringMode == "sum",
		disabled:      map[int]bool{},
		detect:        map[int]bool{},
	}
	applyPaths(pol, e.cfg.Paths, reqPath)

	if sites := e.sites.Load(); sites != nil {
		if so := lookupSite(*sites, host); so != nil {
			if so.Mode != "" {
				pol.mode = modeOf(so.Mode)
			}
			if so.Paranoia != 0 {
				pol.paranoia = uint8(clampPL(so.Paranoia))
			}
			if so.Threshold != 0 {
				pol.threshold = so.Threshold
			}
			for _, id := range so.DisabledRules {
				pol.disabled[id] = true
			}
			for _, id := range so.DetectRules {
				pol.detect[id] = true
			}
			pol.exclusions = append(pol.exclusions, buildExclusions(so.Exclusions)...)
			applyPaths(pol, so.Paths, reqPath)
		}
	}
	return pol
}

func applyPaths(pol *policy, paths []PathOverride, reqPath string) {
	for _, p := range paths {
		if !pathMatches(p, reqPath) {
			continue
		}
		if p.Mode != "" {
			pol.mode = modeOf(p.Mode)
		}
		if p.Paranoia != 0 {
			pol.paranoia = uint8(clampPL(p.Paranoia))
		}
		if p.Threshold != 0 {
			pol.threshold = p.Threshold
		}
		for _, id := range p.DisabledRules {
			pol.disabled[id] = true
		}
		pol.exclusions = append(pol.exclusions, buildExclusions(p.Exclusions)...)
		return // first matching path override wins at this level
	}
}

func pathMatches(p PathOverride, reqPath string) bool {
	if p.Prefix != "" {
		return strings.HasPrefix(reqPath, p.Prefix)
	}
	if p.Glob != "" {
		ok, _ := path.Match(p.Glob, reqPath)
		return ok
	}
	return false
}

func buildExclusions(cfgs []ExclusionConfig) []exclusion {
	var out []exclusion
	for _, c := range cfgs {
		out = append(out, buildExclusion(c.Path, c.Methods, c.Targets))
	}
	return out
}

// lookupSite finds the override for a host, stripping the port and matching
// a leading wildcard like *.example.com. IPv6 safe via the [host]:port form.
func lookupSite(sites map[string]*SiteOverride, host string) *SiteOverride {
	h := strings.ToLower(host)
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		// strip :port unless it is inside [::1]
		if !strings.HasPrefix(h, "[") || strings.Contains(h[:i], "]") {
			h = h[:i]
		}
	}
	h = strings.Trim(h, "[]")
	if so := sites[h]; so != nil {
		return so
	}
	if dot := strings.IndexByte(h, '.'); dot >= 0 {
		if so := sites["*."+h[dot+1:]]; so != nil {
			return so
		}
	}
	return nil
}

func modeOf(s string) Mode {
	if s == "detect" || s == "shadow" {
		return ModeDetect
	}
	return ModeBlock
}

func clampPL(n int) int {
	if n < 1 {
		return 1
	}
	if n > 4 {
		return 4
	}
	return n
}

func nonZero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func nonZero64(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}

func errf(f string, a ...any) error { return fmt.Errorf(f, a...) }

var _ = time.Now

// Active reports whether the process engine is installed and enabled, so the
// request path knows to use it instead of the legacy sanitizer.
func Active() bool {
	e := Default()
	return e != nil && e.cfg.Enabled && e.cur.Load() != nil
}
