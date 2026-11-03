package secrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Dir reads secrets from files under a directory, one file per path, the
// way sops-nix or systemd credentials lay them out on a host: users/alice
// is <dir>/users/alice.
type Dir string

// Get returns the content of path's file, without a trailing newline.
// A missing file is an error matching fs.ErrNotExist.
func (d Dir) Get(path string) (string, error) {
	root, err := os.OpenRoot(string(d))
	if err != nil {
		return "", fmt.Errorf("secrets dir: %w", err)
	}
	defer root.Close()
	data, err := root.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("secret %s: no file %s in %s: %w", path, path, d, fs.ErrNotExist)
		}
		return "", fmt.Errorf("secret %s: %w", path, err)
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}
