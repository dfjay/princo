package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/dfjay/princo/internal/config"
)

// configFiles are the files --config names, in the order they merge.
type configFiles struct {
	paths []string
	data  [][]byte
}

func readConfigFiles(global *globalFlags) (*configFiles, error) {
	c := &configFiles{paths: global.ConfigPaths}
	for _, p := range c.paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		c.data = append(c.data, data)
	}
	return c, nil
}

// config merges the files.
func (c *configFiles) config() (*config.Config, error) {
	files := make([]config.File, len(c.paths))
	for i, p := range c.paths {
		files[i] = config.File{Path: p, Data: c.data[i]}
	}
	return config.Merge(files)
}

// last is the index of the last file, which new entries go to.
func (c *configFiles) last() int { return len(c.paths) - 1 }

// with returns c with file i's content replaced by data.
func (c *configFiles) with(i int, data []byte) *configFiles {
	out := &configFiles{paths: c.paths, data: slices.Clone(c.data)}
	out.data[i] = data
	return out
}

// save writes the files that differ from prev's, all or none: each is
// staged first, and if replacing one fails, the ones replaced get prev's
// content back.
func (c *configFiles) save(prev *configFiles) error {
	type staged struct {
		i           int
		target, tmp string
	}
	var stage []staged
	defer func() {
		for _, s := range stage {
			_ = os.Remove(s.tmp)
		}
	}()
	for i, p := range c.paths {
		if bytes.Equal(c.data[i], prev.data[i]) {
			continue
		}
		target, err := filepath.EvalSymlinks(p)
		if err != nil {
			return err
		}
		tmp, err := stageFile(target, c.data[i])
		if err != nil {
			return err
		}
		stage = append(stage, staged{i, target, tmp})
	}
	for n, s := range stage {
		if err := os.Rename(s.tmp, s.target); err != nil {
			for _, done := range stage[:n] {
				if rerr := saveFile(done.target, prev.data[done.i]); rerr != nil {
					err = errors.Join(err, fmt.Errorf("restoring %s: %w", c.paths[done.i], rerr))
				}
			}
			return err
		}
	}
	return nil
}

// name is file i's name, for messages.
func (c *configFiles) name(i int) string { return filepath.Base(c.paths[i]) }

// saveFile replaces the file at path with data.
func saveFile(path string, data []byte) error {
	tmp, err := stageFile(path, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// stageFile writes data to a temporary file beside path, with its mode.
func stageFile(path string, data []byte) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".princo.yaml.*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err = errors.Join(err, f.Chmod(info.Mode().Perm()), f.Close()); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
