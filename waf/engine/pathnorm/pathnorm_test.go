package pathnorm

import "testing"

func TestDetect(t *testing.T) {
	hits := []string{
		"../../etc/passwd", "..\\..\\windows\\win.ini", "....//....//etc/passwd",
		"..;/..;/etc/passwd", "/var/www/html/../../../etc/shadow", "foo/../../../bar",
		"/etc/passwd", "/proc/self/environ", "c:\\windows\\system32\\cmd.exe",
		"....\\\\....\\\\boot.ini", "index.php?file=../../../../etc/passwd",
	}
	for _, h := range hits {
		if _, ok := Detect([]byte(h)); !ok {
			t.Errorf("MISS: %q", h)
		}
	}
	clean := []string{
		"/index.php", "/api/users/1", "normal/path/file.txt", "my..file.txt",
		"a.b.c", "version 1.2.3", "photo..jpg", "/home", "file.tar.gz",
		"e.t.a. is 5 min", "in a sentence about relative paths, no slash..here",
		"3...2...1", "the u.s.a.",
	}
	for _, c := range clean {
		if m, ok := Detect([]byte(c)); ok {
			t.Errorf("FALSE POSITIVE: %q -> %s", c, m.Reason)
		}
	}
}

func FuzzDetect(f *testing.F) {
	f.Add("../../etc/passwd")
	f.Add("....//")
	f.Fuzz(func(t *testing.T, s string) { Detect([]byte(s)) })
}
