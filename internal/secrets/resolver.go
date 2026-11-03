package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Resolver finds secrets by princo's logical paths (users/alice,
// nodes/de/reality, ...). Each path is looked up in the most specific
// mapping whose pattern matches, or in the default age file.
//
// Files are decrypted on first use and kept in memory.
type Resolver struct {
	// Recipients is the file of age public keys that age files are
	// encrypted to when written.
	Recipients string

	dirs         []string
	identityPath string
	mappings     []Mapping
	cache        map[string]map[string]any

	// decrypt opens a file of the given kind; replaceable in tests.
	decrypt func(kind, path, identityPath string) (map[string]any, error)
}

// Mapping sends logical paths matching Pattern to Target.
//
// Pattern is a path, optionally ending in `*` to match any rest; of those
// matching a path, an exact one wins, then the longest. Target is
// `sops:<file>` or `age:<file>`, optionally followed by `#<key>`; a `*` in
// the key is replaced by what the pattern's `*` matched. Without a key, the
// key is the matched rest (or the whole path for an exact pattern). Files
// are relative to the directory of the config file that has the mapping.
type Mapping struct {
	Pattern string
	Target  string
	// File is the index of that config file.
	File int
}

// DefaultFile is the age file used for paths no mapping covers.
const DefaultFile = "secrets.age"

// NewResolver checks the mappings and returns a resolver for files
// relative to dirs, the config files' directories in merge order, with the
// default age file in the last one. identityPath is the age identity.
func NewResolver(dirs []string, identityPath string, mappings []Mapping) (*Resolver, error) {
	if len(dirs) == 0 {
		return nil, fmt.Errorf("secrets: no config directories")
	}
	abs := make([]string, len(dirs))
	for i, d := range dirs {
		var err error
		if abs[i], err = filepath.Abs(d); err != nil {
			return nil, err
		}
	}
	for _, m := range mappings {
		if strings.Contains(strings.TrimSuffix(m.Pattern, "*"), "*") {
			return nil, fmt.Errorf("secrets: pattern %q: `*` is only allowed at the end", m.Pattern)
		}
		if _, _, _, err := ParseLocation(m.Target); err != nil {
			return nil, fmt.Errorf("secrets: %s: %w", m.Pattern, err)
		}
		if m.File < 0 || m.File >= len(dirs) {
			return nil, fmt.Errorf("secrets: %s: config file %d of %d", m.Pattern, m.File, len(dirs))
		}
	}
	return &Resolver{
		dirs:         abs,
		identityPath: identityPath,
		mappings:     mappings,
		cache:        map[string]map[string]any{},
		decrypt:      decryptFile,
	}, nil
}

// Get resolves a logical path.
func (r *Resolver) Get(path string) (string, error) {
	if err := CheckPath(path); err != nil {
		return "", err
	}
	location, dir := r.Where(path)
	kind, file, key, err := ParseLocation(location)
	if err != nil {
		return "", err
	}
	values, err := r.open(kind, r.abs(file, dir))
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
	location, _ := r.Where(path)
	return location
}

// Identity is where path is stored, with its file as an absolute path:
// paths with the same identity share a value.
func (r *Resolver) Identity(path string) string {
	location, dir := r.Where(path)
	kind, file, key, err := ParseLocation(location)
	if err != nil {
		return location
	}
	return kind + ":" + r.abs(file, dir) + "#" + key
}

// Where returns where path is stored, and the index of the config file its
// file is relative to.
func (r *Resolver) Where(path string) (location string, file int) {
	best, bestRest := -1, ""
	for i, m := range r.mappings {
		rest, ok := match(m.Pattern, path)
		if ok && (best < 0 || moreSpecific(m.Pattern, r.mappings[best].Pattern)) {
			best, bestRest = i, rest
		}
	}
	if best < 0 {
		return "age:" + DefaultFile + "#" + path, len(r.dirs) - 1
	}
	m := r.mappings[best]
	if _, _, key, _ := ParseLocation(m.Target); key != "" {
		return strings.Replace(m.Target, "*", bestRest, 1), m.File
	}
	return m.Target + "#" + bestRest, m.File
}

// moreSpecific reports whether pattern a wins over b when both match.
func moreSpecific(a, b string) bool {
	aPrefix, aWild := strings.CutSuffix(a, "*")
	bPrefix, bWild := strings.CutSuffix(b, "*")
	if aWild != bWild {
		return !aWild
	}
	return len(aPrefix) > len(bPrefix)
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

// CheckPath rejects what isn't a secret path, such as a storage location.
func CheckPath(path string) error {
	if isLocation(path) {
		return fmt.Errorf("%s: a storage location, not a secret path; map a path to it in the secrets block", path)
	}
	if !pathRe.MatchString(path) {
		return fmt.Errorf("secret path %q: want parts of letters, digits, - and _ joined by /, like users/alice", path)
	}
	return nil
}

// pathRe is a secret path. No dots: stores split keys at them, and a
// secrets dir reads paths as files.
var pathRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)

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

// Has reports whether path has a value. A missing age file has none; a
// missing sops file is an error, since princo can't create one.
func (r *Resolver) Has(path string) (bool, error) {
	location, dir := r.Where(path)
	kind, file, _, err := ParseLocation(location)
	if err != nil {
		return false, err
	}
	if kind == "age" {
		if _, err := os.Stat(r.abs(file, dir)); errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
	}
	_, err = r.Get(path)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// Set stores value at path, in the file Get looks it up in: a sops file
// through `sops set`, an age file encrypted to Recipients.
func (r *Resolver) Set(path, value string) error { return r.write(path, &value) }

// Delete removes path from the file Get looks it up in.
func (r *Resolver) Delete(path string) error { return r.write(path, nil) }

// write sets path to value, or removes it when value is nil.
func (r *Resolver) write(path string, value *string) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	location, dir := r.Where(path)
	kind, file, key, err := ParseLocation(location)
	if err != nil {
		return err
	}
	file = r.abs(file, dir)
	delete(r.cache, kind+":"+file)
	if kind == "sops" {
		if value == nil {
			return runSops(nil, "unset", file, sopsIndex(key))
		}
		v, err := json.Marshal(*value)
		if err != nil {
			return err
		}
		// On stdin, the value stays out of process listings.
		return runSops(v, "set", "--value-stdin", file, sopsIndex(key))
	}

	if r.Recipients == "" {
		return fmt.Errorf("write %s: no recipients file to encrypt to", file)
	}
	if err := CheckRecipients(r.identityPath, r.Recipients); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	values := map[string]any{}
	if _, err := os.Stat(file); err == nil {
		if values, err = r.decrypt(kind, file, r.identityPath); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s := NewStore(values)
	if value == nil {
		err = s.Delete(key)
	} else {
		err = s.Set(key, *value)
	}
	if err != nil {
		return err
	}
	return Save(file, r.Recipients, s.values)
}

// sopsIndex turns a key such as a/b into sops' ["a"]["b"].
func sopsIndex(key string) string {
	var b strings.Builder
	for _, part := range splitPath(key) {
		q, _ := json.Marshal(part)
		b.WriteString("[" + string(q) + "]")
	}
	return b.String()
}

func runSops(stdin []byte, args ...string) error {
	bin, err := exec.LookPath("sops")
	if err != nil {
		return fmt.Errorf("sops %s: sops is not installed", strings.Join(args, " "))
	}
	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sops %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// abs is file in the directory of config file dir.
func (r *Resolver) abs(file string, dir int) string {
	if filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(r.dirs[dir], file)
}

func (r *Resolver) open(kind, path string) (map[string]any, error) {
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
