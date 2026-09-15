package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"rhinowaf/waf/engine/rulefile"
	"rhinowaf/waf/engine/rulesets"
)

// Loader compiles a ruleset from the embedded defaults plus optional dirs.
type Loader struct {
	RulesDir string // replaces the embedded set when non-empty
	ExtraDir string // layered on top of whichever base is used
}

// Load reads and compiles. The data loader resolves @data/foo.txt from the
// same source the rules came from, falling back to the embedded data.
func (l Loader) Load() (*Ruleset, error) {
	var files []*rulefile.File
	load := l.dataLoader()

	baseFiles, err := l.baseFiles()
	if err != nil {
		return nil, err
	}
	for _, bf := range baseFiles {
		f, err := rulefile.Parse(bytes.NewReader(bf.data), bf.name)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	if l.ExtraDir != "" {
		extra, err := readDirRules(l.ExtraDir)
		if err == nil {
			for _, bf := range extra {
				f, perr := rulefile.Parse(bytes.NewReader(bf.data), bf.name)
				if perr != nil {
					return nil, perr
				}
				files = append(files, f)
			}
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no rule files found")
	}
	return compile(files, load)
}

type namedFile struct {
	name string
	data []byte
}

func (l Loader) baseFiles() ([]namedFile, error) {
	if l.RulesDir != "" {
		return readDirRules(l.RulesDir)
	}
	entries, err := fs.ReadDir(rulesets.FS, ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".rules") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []namedFile
	for _, n := range names {
		b, err := rulesets.FS.ReadFile(n)
		if err != nil {
			return nil, err
		}
		out = append(out, namedFile{name: n, data: b})
	}
	return out, nil
}

func readDirRules(dir string) ([]namedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".rules") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []namedFile
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, namedFile{name: n, data: b})
	}
	return out, nil
}

// dataLoader resolves @data references: rules dir first, then extra dir,
// then the embedded data.
func (l Loader) dataLoader() dataLoader {
	return func(path string) ([][]byte, error) {
		path = strings.TrimPrefix(path, "@")
		try := []string{}
		if l.RulesDir != "" {
			try = append(try, filepath.Join(l.RulesDir, path))
		}
		if l.ExtraDir != "" {
			try = append(try, filepath.Join(l.ExtraDir, path))
		}
		for _, p := range try {
			if b, err := os.ReadFile(p); err == nil {
				return splitLines(b), nil
			}
		}
		if b, err := rulesets.FS.ReadFile(path); err == nil {
			return splitLines(b), nil
		}
		return nil, fmt.Errorf("data file %q not found", path)
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		out = append(out, append([]byte(nil), line...))
	}
	return out
}

// Reload recompiles and swaps the ruleset atomically. A bad file leaves the
// old set in place and returns the error, so /reload never drops protection.
func (e *Engine) Reload(l Loader) error {
	rs, err := l.Load()
	if err != nil {
		return err
	}
	e.cur.Store(rs)
	return nil
}
