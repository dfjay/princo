package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Resolver finds secrets by princo's logical paths (users/alice,
// nodes/de/reality, ...). Each path is looked up in the first mapping whose
// pattern matches, or in the default age file. A path may also be a
// location itself: `sops:file.yaml#key` or `age:file#key`.
//
// Files are decrypted on first use and kept in memory.
type Resolver struct {
	baseDir      string
	identityPath string
	mappings     []Mapping
	cache        map[string]map[string]any

	// decrypt opens a file of the given kind; replaceable in tests.
	decrypt func(kind, path, identityPath string) (map[string]any, error)
}

// Mapping sends logical paths matching Pattern to Target.
//
// Pattern is a path, optionally ending in `*` to match any rest. Target is
// `sops:<file>` or `age:<file>`, optionally followed by `#<key>`; a `*` in
// the key is replaced by what the pattern's `*` matched. Without a key, the
// key is the matched rest (or the whole path for an exact pattern). Files
// are relative to the directory of princo.yaml.
type Mapping struct {
	Pattern string
	Target  string
}

// DefaultFile is the age file used for paths no mapping covers.
const DefaultFile = "secrets.age"

// NewResolver checks the mappings and returns a resolver for files under
// baseDir; identityPath is the age identity for age files.
func NewResolver(baseDir, identityPath string, mappings []Mapping) (*Resolver, error) {
	for _, m := range mappings {
		if strings.Contains(strings.TrimSuffix(m.Pattern, "*"), "*") {
			return nil, fmt.Errorf("secrets: pattern %q: `*` is only allowed at the end", m.Pattern)
		}
		if _, _, _, err := ParseLocation(m.Target); err != nil {
			return nil, fmt.Errorf("secrets: %s: %w", m.Pattern, err)
		}
	}
	return &Resolver{
		baseDir:      baseDir,
		identityPath: identityPath,
		mappings:     mappings,
		cache:        map[string]map[string]any{},
		decrypt:      decryptFile,
	}, nil
}

// Get resolves a logical path or an explicit location.
func (r *Resolver) Get(path string) (string, error) {
	location := r.Locate(path)
	kind, file, key, err := ParseLocation(location)
	if err != nil {
		return "", err
	}
	values, err := r.open(kind, file)
	if err != nil {
		return "", err
	}
	v, err := lookup(values, key)
	if err != nil {
		if location != path {
			return "", fmt.Errorf("%s (looked up as %s): %w", path, location, err)
		}
		return "", err
	}
	return v, nil
}

// Locate returns where path is looked up: a location like sops:file#key.
func (r *Resolver) Locate(path string) string {
	if isLocation(path) {
		return path
	}
	for _, m := range r.mappings {
		rest, ok := match(m.Pattern, path)
		if !ok {
			continue
		}
		if _, _, key, _ := ParseLocation(m.Target); key != "" {
			return strings.Replace(m.Target, "*", rest, 1)
		}
		return m.Target + "#" + rest
	}
	return "age:" + DefaultFile + "#" + path
}

// match reports whether path fits pattern and what `*` covered; for an
// exact pattern that's the whole path.
func match(pattern, path string) (string, bool) {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		rest, ok := strings.CutPrefix(path, prefix)
		return rest, ok && rest != ""
	}
	return path, pattern == path
}

func isLocation(s string) bool {
	return strings.HasPrefix(s, "sops:") || strings.HasPrefix(s, "age:")
}

// parseLocation splits `kind:file#key`; key may be empty.
func ParseLocation(s string) (kind, file, key string, err error) {
	kind, rest, ok := strings.Cut(s, ":")
	if !ok || (kind != "sops" && kind != "age") {
		return "", "", "", fmt.Errorf("secret location %q: want sops:<file>[#key] or age:<file>[#key]", s)
	}
	file, key, _ = strings.Cut(rest, "#")
	if file == "" {
		return "", "", "", fmt.Errorf("secret location %q: file is empty", s)
	}
	return kind, file, key, nil
}

func (r *Resolver) open(kind, file string) (map[string]any, error) {
	path := file
	if !filepath.IsAbs(path) {
		path = filepath.Join(r.baseDir, file)
	}
	id := kind + ":" + path
	if v, ok := r.cache[id]; ok {
		return v, nil
	}
	v, err := r.decrypt(kind, path, r.identityPath)
	if err != nil {
		return nil, err
	}
	r.cache[id] = v
	return v, nil
}

func decryptFile(kind, path, identityPath string) (map[string]any, error) {
	if kind == "age" {
		s, err := Open(path, identityPath)
		if err != nil {
			return nil, err
		}
		return s.values, nil
	}
	return decryptSops(path)
}

// decryptSops runs the sops CLI, so every key type it supports works
// (age, PGP on a YubiKey, cloud KMS) without princo knowing about them.
func decryptSops(path string) (map[string]any, error) {
	bin, err := exec.LookPath("sops")
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: sops is not installed", path)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "--decrypt", "--output-type", "json", path)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops --decrypt %s: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}
	var values map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &values); err != nil {
		return nil, fmt.Errorf("decrypt %s: sops output is not a JSON object: %w", path, err)
	}
	return values, nil
}
