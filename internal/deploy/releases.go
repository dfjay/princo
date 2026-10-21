package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
)

// InstallReleases puts the whole of each engine's pinned release for a
// Debian architecture into dir, to check rendered configs on.
func InstallReleases(ctx context.Context, client *http.Client, arch, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(engines)) {
		a, ok := engines[name].archive(arch)
		if !ok {
			return fmt.Errorf("there's no %s for %s", name, arch)
		}
		data, err := Fetch(ctx, client, a.URL)
		if err != nil {
			return err
		}
		files, err := a.unpack(data, func(string) bool { return true })
		if err != nil {
			return err
		}
		for file, data := range files {
			if err := os.WriteFile(filepath.Join(dir, file), data, 0o755); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReleaseDigests downloads an engine's release at version for each
// architecture princo deploy runs it on, and returns their SHA-256s to
// pin.
func ReleaseDigests(ctx context.Context, client *http.Client, name, version string) (map[string]string, error) {
	e, ok := engines[name]
	if !ok {
		return nil, fmt.Errorf("princo deploy can't run engine %s", name)
	}
	out := map[string]string{}
	for arch := range e.release.SHA256 {
		data, err := Fetch(ctx, client, e.release.url(version, arch))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		out[arch] = hex.EncodeToString(sum[:])
	}
	return out, nil
}
