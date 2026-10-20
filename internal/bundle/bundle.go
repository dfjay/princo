// Package bundle is what princo deploy ships to a host: files and the
// systemd units that run from them, and how the host applies them.
package bundle

import (
	"fmt"
	"io/fs"
	"path"
)

// Format changes when an older princo would apply a newer bundle wrongly.
const Format = 1

type Bundle struct {
	Format int    `json:"format"`
	Node   string `json:"node"`
	// Partial bundles remove no files and aren't recorded as the last apply.
	Partial bool   `json:"partial,omitempty"`
	Dirs    []Dir  `json:"dirs"`
	Files   []File `json:"files"`
	// Units restart in this order.
	Units []Unit `json:"units"`
}

// Dir is a directory whose mode or group isn't 0755 root's, as parents get.
type Dir struct {
	Path string      `json:"path"`
	Mode fs.FileMode `json:"mode"`
	// Group owns the directory; root when empty.
	Group string `json:"group,omitempty"`
}

type File struct {
	Path string      `json:"path"`
	Mode fs.FileMode `json:"mode"`
	// Group owns the file; root when empty.
	Group string `json:"group,omitempty"`
	Data  []byte `json:"data"`
}

// Unit is a systemd unit, enabled at boot, that runs from some of the
// bundle's files.
type Unit struct {
	Name string `json:"name"`
	// Files restart the unit when they change, or reload it with Reload.
	Files  []string `json:"files"`
	Reload bool     `json:"reload,omitempty"`
	// Check runs before the unit restarts; when it fails, the apply is undone.
	Check []string `json:"check,omitempty"`
}

func (b *Bundle) validate() error {
	if b.Format != Format {
		return fmt.Errorf("bundle format %d, but this princo applies format %d: install the deploying princo's version", b.Format, Format)
	}
	seen := map[string]bool{}
	checkPath := func(p string, mode fs.FileMode) error {
		if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
			return fmt.Errorf("bundle: path %q isn't absolute and clean", p)
		}
		if seen[p] {
			return fmt.Errorf("bundle: %s appears twice", p)
		}
		seen[p] = true
		if mode&^fs.ModePerm != 0 {
			return fmt.Errorf("bundle: %s has mode %v; only permission bits are allowed", p, mode)
		}
		return nil
	}
	for _, d := range b.Dirs {
		if err := checkPath(d.Path, d.Mode); err != nil {
			return err
		}
	}
	files := map[string]bool{}
	for _, f := range b.Files {
		if err := checkPath(f.Path, f.Mode); err != nil {
			return err
		}
		files[f.Path] = true
	}
	for _, u := range b.Units {
		for _, f := range u.Files {
			if !files[f] {
				return fmt.Errorf("bundle: unit %s runs from %s, which the bundle lacks", u.Name, f)
			}
		}
	}
	return nil
}
