// Package pathnorm spots directory traversal and access to sensitive
// absolute paths. It runs after the rule's decode chain, so "%2e%2e%2f"
// has already become "../" by the time it gets here; what it adds is the
// tricks a plain decode misses: "....//" that collapses to "../", "..;/"
// that some servers treat as "../", and matching against the obvious
// unix/windows targets.
package pathnorm

import "strings"

type Match struct {
	Reason string
	Start  int
	End    int
}

// sensitive absolute targets. these are files nobody requests by accident.
var absTargets = []string{
	"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group", "/etc/issue",
	"/proc/self/", "/proc/version", "/proc/cmdline", "/proc/net/",
	"/var/log/", "/var/www/", "/root/.ssh", "/home/", "/.ssh/id_",
	"/windows/win.ini", "/windows/system32", "/boot.ini", "/inetpub/",
	"\\windows\\", "\\boot.ini", "c:\\", "c:/", "/usr/local/", "/private/etc/",
}

// Detect returns a match when v is a traversal or hits a sensitive path.
func Detect(v []byte) (Match, bool) {
	s := string(v)
	// literal traversal, both slash directions
	if i := indexTraversal(s); i >= 0 {
		return Match{Reason: "path traversal", Start: i, End: min(i+3, len(s))}, true
	}
	low := strings.ToLower(s)
	for _, t := range absTargets {
		if i := strings.Index(low, t); i >= 0 {
			return Match{Reason: "sensitive path " + t, Start: i, End: i + len(t)}, true
		}
	}
	return Match{}, false
}

// indexTraversal finds ../ ..\ and the collapsing tricks. Returns the byte
// offset or -1.
func indexTraversal(s string) int {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '.' || s[i+1] != '.' {
			continue
		}
		// what follows the .. decides
		j := i + 2
		if j >= len(s) {
			continue
		}
		switch c := s[j]; c {
		case '/', '\\':
			return i
		case ';': // ..;/ jetty/tomcat trick
			if j+1 < len(s) && (s[j+1] == '/' || s[j+1] == '\\') {
				return i
			}
		case '.': // ....// collapses to ../ after one normalization
			for k := j; k < len(s) && k < j+4; k++ {
				if s[k] == '/' || s[k] == '\\' {
					return i
				}
			}
		}
	}
	// leading ".." as the whole segment (e.g. "..%c0%af" left ".." then junk)
	if s == ".." || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "..\\") {
		return 0
	}
	return -1
}
