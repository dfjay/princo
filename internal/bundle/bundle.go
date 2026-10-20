// Package bundle is what princo deploy ships to a host, and how the host
// applies it: files to write and the systemd units they belong to. It
// knows nothing about engines or nginx; the deploy decides what goes in,
// so a host's princo only has to understand the bundle's Format.
package bundle

import (
	"fmt"
	"io/fs"
	"path"
)

// Format is the bundle format this princo writes and applies. It changes
// only when an older princo would apply a newer bundle wrongly.
const Format = 1

type Bundle struct {
	Format int    `json:"format"`
	Node   string `json:"node"`
	// Partial bundles only write: they remove no file and leave the record
	// of the last apply alone, so the next whole bundle still knows what
	// to remove.
	Partial bool   `json:"partial,omitempty"`
	Dirs    []Dir  `json:"dirs"`
	Files   []File `json:"files"`
	// Units restart in this order.
	Units []Unit `json:"units"`
}

// Dir is a directory that needs a mode or group other than the 0755 root
// one that parent directories get.
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

// Unit is a systemd unit that runs from some of the bundle's files.
type Unit struct {
	Name string `json:"name"`
	// Enable starts the unit at boot.
	Enable bool `json:"enable,omitempty"`
	// Files restart the unit when they change, or reload it with Reload.
	Files  []string `json:"files"`
	Reload bool     `json:"reload,omitempty"`
	// Check is a command that runs before the unit restarts or reloads,
	// e.g. nginx -t. When it fails, the apply is undone.
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
		if u.Name == "" {
			return fmt.Errorf("bundle: a unit has no name")
		}
		for _, f := range u.Files {
			if !files[f] {
				return fmt.Errorf("bundle: unit %s runs from %s, which the bundle lacks", u.Name, f)
			}
		}
		if len(u.Check) > 0 && u.Check[0] == "" {
			return fmt.Errorf("bundle: unit %s has an empty check command", u.Name)
		}
	}
	return nil
}
