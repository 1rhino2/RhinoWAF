package smuggling

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Detection patterns for smuggling attempts
var (
	teChunkedRegex      = regexp.MustCompile(`(?i)chunked`)
	spaceInHeaderRegex  = regexp.MustCompile(`[\t\r\n\v\f]`)
	multipleSpacesRegex = regexp.MustCompile(`\s{2,}`)
	hexPrefixRegex      = regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)
	conflictingTERegex  = regexp.MustCompile(`(?i)chunked.*,.*chunked`)
)

type ViolationType string

const (
	ViolationCLTE              ViolationType = "CL_TE_CONFLICT"
	ViolationTECL              ViolationType = "TE_CL_CONFLICT"
	ViolationMultipleCL        ViolationType = "MULTIPLE_CL"
	ViolationMultipleTE        ViolationType = "MULTIPLE_TE"
	ViolationInvalidCL         ViolationType = "INVALID_CL"
	ViolationInvalidTE         ViolationType = "INVALID_TE"
	ViolationObfuscatedCL      ViolationType = "OBFUSCATED_CL"
	ViolationObfuscatedTE      ViolationType = "OBFUSCATED_TE"
	ViolationWhitespaceInCL    ViolationType = "WHITESPACE_IN_CL"
	ViolationWhitespaceInTE    ViolationType = "WHITESPACE_IN_TE"
	ViolationDuplicateTE       ViolationType = "DUPLICATE_TE"
	ViolationConflictingTE     ViolationType = "CONFLICTING_TE"
	ViolationCLZeroWithTE      ViolationType = "CL_ZERO_WITH_TE"
	ViolationNegativeCL        ViolationType = "NEGATIVE_CL"
	ViolationMalformedChunked  ViolationType = "MALFORMED_CHUNKED"
	ViolationHTTP09WithHeaders ViolationType = "HTTP09_WITH_HEADERS"
	ViolationInvalidProtocol   ViolationType = "INVALID_PROTOCOL"
)

type Violation struct {
	Type        ViolationType
	Description string
	Severity    int // 1-5, 5 being critical
	Headers     map[string][]string
}

type Detector struct {
	EnableStrictMode bool
	LogViolations    bool
	BlockOnSeverity  int // Block if severity >= this value
}

func NewDetector(strictMode bool, logViolations bool, blockSeverity int) *Detector {
	return &Detector{
		EnableStrictMode: strictMode,
		LogViolations:    logViolations,
		BlockOnSeverity:  blockSeverity,
	}
}

// Check performs comprehensive smuggling detection on the request
func (d *Detector) Check(r *http.Request) ([]Violation, bool) {
	violations := []Violation{}
	clHeaders := r.Header.Values("Content-Length")
	teHeaders := r.Header.Values("Transfer-Encoding")

	violations = append(violations, d.checkMultipleHeaders(clHeaders, teHeaders)...)
	violations = append(violations, d.checkCLTEConflict(clHeaders, teHeaders)...)
	violations = append(violations, d.validateContentLength(clHeaders, teHeaders)...)
	violations = append(violations, d.validateTransferEncoding(teHeaders)...)
	violations = append(violations, d.checkProtocolViolations(r)...)

	shouldBlock := d.shouldBlockRequest(violations)
	return violations, shouldBlock
}

func (d *Detector) checkMultipleHeaders(clHeaders, teHeaders []string) []Violation {
	violations := []Violation{}

	if len(clHeaders) > 1 {
		violations = append(violations, Violation{
			Type:        ViolationMultipleCL,
			Description: fmt.Sprintf("multiple Content-Length headers detected: %v", clHeaders),
			Severity:    5,
			Headers:     map[string][]string{"Content-Length": clHeaders},
		})
	}

	if len(teHeaders) > 1 {
		uniqueTE := make(map[string]bool)
		for _, te := range teHeaders {
			uniqueTE[strings.ToLower(strings.TrimSpace(te))] = true
		}
		if len(uniqueTE) > 1 {
			violations = append(violations, Violation{
				Type:        ViolationMultipleTE,
				Description: fmt.Sprintf("multiple conflicting Transfer-Encoding headers: %v", teHeaders),
				Severity:    5,
				Headers:     map[string][]string{"Transfer-Encoding": teHeaders},
			})
		} else {
			violations = append(violations, Violation{
				Type:        ViolationDuplicateTE,
				Description: fmt.Sprintf("duplicate Transfer-Encoding headers: %v", teHeaders),
				Severity:    4,
				Headers:     map[string][]string{"Transfer-Encoding": teHeaders},
			})
		}
	}

	return violations
}

func (d *Detector) checkCLTEConflict(clHeaders, teHeaders []string) []Violation {
	violations := []Violation{}

	if len(clHeaders) > 0 && len(teHeaders) > 0 {
		cl := clHeaders[0]
		te := teHeaders[0]

		if teChunkedRegex.MatchString(te) {
			violations = append(violations, Violation{
				Type:        ViolationCLTE,
				Description: fmt.Sprintf("CL.TE smuggling detected: CL=%s, TE=%s", cl, te),
				Severity:    5,
				Headers: map[string][]string{
					"Content-Length":    {cl},
					"Transfer-Encoding": {te},
				},
			})
		}

		violations = append(violations, Violation{
			Type:        ViolationTECL,
			Description: fmt.Sprintf("TE.CL smuggling detected: TE=%s, CL=%s", te, cl),
			Severity:    5,
			Headers: map[string][]string{
				"Transfer-Encoding": {te},
				"Content-Length":    {cl},
			},
		})
	}

	return violations
}

func (d *Detector) validateContentLength(clHeaders, teHeaders []string) []Violation {
	violations := []Violation{}

	for _, cl := range clHeaders {
		if spaceInHeaderRegex.MatchString(cl) {
			violations = append(violations, Violation{
				Type:        ViolationWhitespaceInCL,
				Description: fmt.Sprintf("whitespace or control chars in Content-Length: %q", cl),
				Severity:    5,
				Headers:     map[string][]string{"Content-Length": {cl}},
			})
		}

		if multipleSpacesRegex.MatchString(cl) || hexPrefixRegex.MatchString(cl) {
			violations = append(violations, Violation{
				Type:        ViolationObfuscatedCL,
				Description: fmt.Sprintf("obfuscated Content-Length value: %q", cl),
				Severity:    5,
				Headers:     map[string][]string{"Content-Length": {cl}},
			})
		}

		clInt, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err != nil {
			violations = append(violations, Violation{
				Type:        ViolationInvalidCL,
				Description: fmt.Sprintf("invalid Content-Length value: %q", cl),
				Severity:    5,
				Headers:     map[string][]string{"Content-Length": {cl}},
			})
		} else if clInt < 0 {
			violations = append(violations, Violation{
				Type:        ViolationNegativeCL,
				Description: fmt.Sprintf("negative Content-Length value: %d", clInt),
				Severity:    5,
				Headers:     map[string][]string{"Content-Length": {cl}},
			})
		} else if clInt == 0 && len(teHeaders) > 0 {
			violations = append(violations, Violation{
				Type:        ViolationCLZeroWithTE,
				Description: "Content-Length: 0 combined with Transfer-Encoding (bypass attempt)",
				Severity:    4,
				Headers: map[string][]string{
					"Content-Length":    {cl},
					"Transfer-Encoding": teHeaders,
				},
			})
		}
	}

	return violations
}

func (d *Detector) validateTransferEncoding(teHeaders []string) []Violation {
	violations := []Violation{}

	for _, te := range teHeaders {
		if spaceInHeaderRegex.MatchString(te) {
			violations = append(violations, Violation{
				Type:        ViolationWhitespaceInTE,
				Description: fmt.Sprintf("whitespace or control chars in Transfer-Encoding: %q", te),
				Severity:    5,
				Headers:     map[string][]string{"Transfer-Encoding": {te}},
			})
		}

		if multipleSpacesRegex.MatchString(te) {
			violations = append(violations, Violation{
				Type:        ViolationObfuscatedTE,
				Description: fmt.Sprintf("obfuscated Transfer-Encoding value: %q", te),
				Severity:    5,
				Headers:     map[string][]string{"Transfer-Encoding": {te}},
			})
		}

		if conflictingTERegex.MatchString(te) {
			violations = append(violations, Violation{
				Type:        ViolationConflictingTE,
				Description: fmt.Sprintf("conflicting chunked encodings: %q", te),
				Severity:    5,
				Headers:     map[string][]string{"Transfer-Encoding": {te}},
			})
		}

		if !d.isValidTransferEncoding(te) {
			violations = append(violations, Violation{
				Type:        ViolationInvalidTE,
				Description: fmt.Sprintf("invalid Transfer-Encoding value: %q", te),
				Severity:    4,
				Headers:     map[string][]string{"Transfer-Encoding": {te}},
			})
		}
	}

	return violations
}

func (d *Detector) isValidTransferEncoding(te string) bool {
	validEncodings := []string{"chunked", "compress", "deflate", "gzip", "identity"}
	encodingParts := strings.Split(strings.ToLower(te), ",")

	for _, part := range encodingParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		valid := false
		for _, validEnc := range validEncodings {
			if part == validEnc {
				valid = true
				break
			}
		}
		if !valid {
			return false
		}
	}

	return true
}

func (d *Detector) checkProtocolViolations(r *http.Request) []Violation {
	violations := []Violation{}

	if r.ProtoMajor == 0 && r.ProtoMinor == 9 && len(r.Header) > 0 {
		violations = append(violations, Violation{
			Type:        ViolationHTTP09WithHeaders,
			Description: "HTTP/0.9 request with headers detected (smuggling attempt)",
			Severity:    5,
			Headers:     map[string][]string{"Proto": {r.Proto}},
		})
	}

	if r.ProtoMajor < 0 || r.ProtoMinor < 0 || r.ProtoMajor > 3 {
		violations = append(violations, Violation{
			Type:        ViolationInvalidProtocol,
			Description: fmt.Sprintf("invalid HTTP protocol version: %s", r.Proto),
			Severity:    4,
			Headers:     map[string][]string{"Proto": {r.Proto}},
		})
	}

	return violations
}

func (d *Detector) shouldBlockRequest(violations []Violation) bool {
	for _, v := range violations {
		if v.Severity >= d.BlockOnSeverity {
			return true
		}
	}
	return false
}

// GetViolationSummary returns a formatted summary of violations
func GetViolationSummary(violations []Violation) string {
	if len(violations) == 0 {
		return "no violations"
	}

	parts := make([]string, len(violations))
	for i, v := range violations {
		parts[i] = fmt.Sprintf("%s (severity: %d)", v.Type, v.Severity)
	}
	return strings.Join(parts, "; ")
}

// IsHighSeverity checks if any violation is high severity (4+)
func IsHighSeverity(violations []Violation) bool {
	for _, v := range violations {
		if v.Severity >= 4 {
			return true
		}
	}
	return false
}
