// Package fleettest loads fixture fleets for tests.
package fleettest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/secrets"
)

// Load builds the fleet in dir from princo.yaml and the plaintext
// secrets.test.yaml next to it.
func Load(t *testing.T, dir string) *fleet.Fleet {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "princo.yaml"))
	require.NoError(t, err)
	cfg, err := config.Parse(data)
	require.NoError(t, err)

	plain, err := os.ReadFile(filepath.Join(dir, "secrets.test.yaml"))
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, yaml.Unmarshal(plain, &values))

	f, err := fleet.Build(cfg, secrets.NewStore(values))
	require.NoError(t, err)
	return f
}
