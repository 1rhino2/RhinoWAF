package engine

import (
	"fmt"
	"strings"

	"rhinowaf/waf/engine/transform"
)

// Phase says when a rule runs. Request phases see the incoming request,
// response phases see what the backend sent back.
type Phase uint8

const (
	PhaseReqHeaders Phase = iota + 1
	PhaseReqBody
	PhaseRespHeaders
	PhaseRespBody
)

func (p Phase) String() string {
	switch p {
	case PhaseReqHeaders:
		return "request-headers"
	case PhaseReqBody:
		return "request-body"
	case PhaseRespHeaders:
		return "response-headers"
	case PhaseRespBody:
		return "response-body"
	}
	return "?"
}

func parsePhase(s string) (Phase, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "request-headers", "req-headers", "headers":
		return PhaseReqHeaders, nil
	case "request-body", "req-body", "body":
		return PhaseReqBody, nil
	case "response-headers", "resp-headers":
		return PhaseRespHeaders, nil
	case "response-body", "resp-body":
		return PhaseRespBody, nil
	}
	return 0, fmt.Errorf("unknown phase %q", s)
}

// Severity doubles as the default score, the way CRS anomaly levels do.
type Severity uint8

const (
	SevNotice   Severity = 2
	SevWarning  Severity = 3
	SevError    Severity = 4
	SevCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
	case SevNotice:
		return "notice"
	case SevWarning:
		return "warning"
	case SevError:
		return "error"
	case SevCritical:
		return "critical"
	}
	return "info"
}

func parseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "notice":
		return SevNotice, nil
	case "warning":
		return SevWarning, nil
	case "error":
		return SevError, nil
	case "critical":
		return SevCritical, nil
	}
	return 0, fmt.Errorf("unknown severity %q", s)
}

// Action is what a matched rule does.
type Action uint8

const (
	ActScore     Action = iota // add to the anomaly score
	ActBlock                   // block now, no matter the score
	ActLog                     // record, do not score
	ActAllow                   // stop, let the request through (whitelist)
	ActChallenge               // force the challenge page
	ActSetVar                  // set a tx variable (rarely used)
)

func (a Action) String() string {
	switch a {
	case ActBlock:
		return "block"
	case ActLog:
		return "log"
	case ActAllow:
		return "allow"
	case ActChallenge:
		return "challenge"
	case ActSetVar:
		return "setvar"
	}
	return "score"
}

func parseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "score":
		return ActScore, nil
	case "block", "deny":
		return ActBlock, nil
	case "log", "pass":
		return ActLog, nil
	case "allow":
		return ActAllow, nil
	case "challenge":
		return ActChallenge, nil
	case "setvar":
		return ActSetVar, nil
	}
	return 0, fmt.Errorf("unknown action %q", s)
}

// Mode lets a single rule (or the whole engine) run in detect mode: it
// records and scores but never blocks.
type Mode uint8

const (
	ModeBlock Mode = iota
	ModeDetect
)

func (m Mode) String() string {
	if m == ModeDetect {
		return "detect"
	}
	return "block"
}

func parseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "block":
		return ModeBlock, nil
	case "detect", "shadow", "detectonly":
		return ModeDetect, nil
	}
	return 0, fmt.Errorf("unknown mode %q", s)
}

// TargetKind is the class of input a rule looks at.
type TargetKind uint8

const (
	TArgs      TargetKind = iota // query + body params, by value
	TArgsNames                   // param names
	TPath
	TRawQuery
	TCookies
	TCookieNames
	THeaders // needs a name
	THeaderNames
	TBody // whole raw body
	TJSON // json string leaves, by value
	TJSONNames
	TXML
	TFilesNames
	TFilesContent
	TUA
	TReferer
	THost
	TMethod
	TContentType
	TRespStatus
	TRespHeaders
	TRespBody
)

var targetNames = map[string]TargetKind{
	"args": TArgs, "args_names": TArgsNames, "argsnames": TArgsNames,
	"path": TPath, "raw_query": TRawQuery, "rawquery": TRawQuery, "query": TRawQuery,
	"cookies": TCookies, "cookie_names": TCookieNames, "cookienames": TCookieNames,
	"headers": THeaders, "header_names": THeaderNames, "headernames": THeaderNames,
	"body": TBody, "json": TJSON, "json_names": TJSONNames, "jsonnames": TJSONNames,
	"xml": TXML, "files_names": TFilesNames, "filesnames": TFilesNames,
	"files_content": TFilesContent, "filescontent": TFilesContent,
	"ua": TUA, "user_agent": TUA, "useragent": TUA, "referer": TReferer, "referrer": TReferer,
	"host": THost, "method": TMethod, "content_type": TContentType, "contenttype": TContentType,
	"resp_status": TRespStatus, "respstatus": TRespStatus,
	"resp_headers": TRespHeaders, "respheaders": TRespHeaders,
	"resp_body": TRespBody, "respbody": TRespBody,
}

var targetKindName = func() map[TargetKind]string {
	m := map[TargetKind]string{}
	for n, k := range targetNames {
		if cur, ok := m[k]; !ok || (strings.Contains(n, "_") && len(n) >= len(cur)) {
			m[k] = n
		}
	}
	return m
}()

func (k TargetKind) String() string { return targetKindName[k] }

// bodyPhase reports whether this target only becomes available once the
// body is read, so the header phase can skip the read when no such rule
// is in play.
func (k TargetKind) needsBody() bool {
	switch k {
	case TArgs, TArgsNames, TJSON, TJSONNames, TXML, TBody, TFilesNames, TFilesContent:
		return true
	}
	return false
}

func (k TargetKind) isResponse() bool {
	return k == TRespStatus || k == TRespHeaders || k == TRespBody
}

// Target is one input selector. Name filters headers[user-agent] or
// args[id], empty means all, a trailing * globs a prefix.
type Target struct {
	Kind TargetKind
	Name string
}

func parseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	name := ""
	if i := strings.IndexByte(s, '['); i >= 0 && strings.HasSuffix(s, "]") {
		name = strings.ToLower(s[i+1 : len(s)-1])
		s = s[:i]
	}
	k, ok := targetNames[strings.ToLower(s)]
	if !ok {
		return Target{}, fmt.Errorf("unknown target %q", s)
	}
	return Target{Kind: k, Name: name}, nil
}

func (t Target) label(actualName string) string {
	if t.Kind == TPath || t.Kind == TRawQuery || t.Kind == TBody || t.Kind == TUA ||
		t.Kind == TReferer || t.Kind == THost || t.Kind == TMethod {
		return t.Kind.String()
	}
	if actualName != "" {
		return t.Kind.String() + ":" + actualName
	}
	return t.Kind.String()
}

// matchesName says whether an actual field name satisfies the target's
// name filter.
func (t Target) matchesName(actual string) bool {
	if t.Name == "" {
		return true
	}
	if strings.HasSuffix(t.Name, "*") {
		return strings.HasPrefix(strings.ToLower(actual), t.Name[:len(t.Name)-1])
	}
	return strings.EqualFold(actual, t.Name)
}

// Cond is one condition. A rule's conds must all match.
type Cond struct {
	Targets  []Target
	Excludes []Target
	Chain    []transform.ID
	ChainID  int
	Op       Operator
	OpText   string
	Negate   bool
	Skip     bool // skip opaque (jwt/base64) values
}

// Rule is a compiled detection rule.
type Rule struct {
	ID         int
	Name       string
	Category   string
	Severity   Severity
	Score      int
	Paranoia   uint8
	Phase      Phase
	Action     Action
	Mode       Mode
	Tags       []string
	Conds      []Cond
	Hints      [][]byte // prefilter literals, nil = always evaluate
	ordinal    int
	disabled   bool        // set by a "disable" directive
	staticExcl []exclusion // exclusions attached at compile time
}
