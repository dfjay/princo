// Package version is princo's version: VERSION, which release-please
// bumps in each release PR, plus the commit for builds between releases.
package version

import (
	_ "embed"
	"runtime/debug"
	"strings"
)

//go:embed VERSION
var number string

// Revision is the commit princo was built from. The Nix package sets it;
// `go build` in a checkout records it itself. Release builds leave it out.
var Revision string

// String is the version, with "+<commit>" for builds between releases.
func String() string {
	n := strings.TrimSpace(number)
	rev := Revision
	if rev == "" {
		rev = vcsRevision()
	}
	if rev == "" {
		return n
	}
	return n + "+" + rev
}

func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value[:min(7, len(s.Value))]
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if rev != "" && modified {
		rev += "-dirty"
	}
	return rev
}
