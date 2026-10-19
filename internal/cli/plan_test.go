package cli

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/secrets"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&stdout)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

// TestPlanThenRender does what a host does: plan says which secrets node de
// needs, only those go into a secrets dir, and render --out writes the
// node's files from it.
func TestPlanThenRender(t *testing.T) {
	configPath := "../../testdata/fleet/princo.yaml"
	out, err := run(t, "--config", configPath, "plan", "--node", "de")
	require.NoError(t, err)
	var plan host.Plan
	require.NoError(t, json.Unmarshal([]byte(out), &plan))

	plain, err := os.ReadFile("../../testdata/fleet/secrets.test.yaml")
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, yaml.Unmarshal(plain, &values))
	store := secrets.NewStore(values)
	secretsDir := t.TempDir()
	for _, s := range plan.Secrets {
		v, err := store.Get(s.Path)
		require.NoError(t, err)
		path := filepath.Join(secretsDir, filepath.FromSlash(s.File))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(v), 0o600))
	}

	outDir := filepath.Join(t.TempDir(), "princo")
	require.NoError(t, os.MkdirAll(filepath.Join(outDir, "stale"), 0o700))
	_, err = run(t, "--config", configPath, "--secrets-dir", secretsDir, "render", "--node", "de", "--out", outDir)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(outDir, plan.Config))
	require.NoError(t, err)
	want, err := os.ReadFile("../../testdata/fleet/golden/server-de.json")
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(got))
	require.FileExists(t, filepath.Join(outDir, host.TokensFile))
	require.NoDirExists(t, filepath.Join(outDir, "stale"), "render --out replaces the dir")

	// A secret the node needs but the dir lacks is named, not rendered as a placeholder.
	require.NoError(t, os.Remove(filepath.Join(secretsDir, "users", "bob")))
	_, err = run(t, "--config", configPath, "--secrets-dir", secretsDir, "render", "--node", "de", "--out", outDir)
	require.ErrorContains(t, err, "secrets missing from "+secretsDir+": users/bob")
	// us doesn't serve the site, and bob's UUID is all it would miss.
	_, err = run(t, "--config", configPath, "--secrets-dir", secretsDir, "render", "--node", "us")
	require.ErrorContains(t, err, "users/bob")
	_, err = run(t, "--config", configPath, "--secrets-dir", secretsDir, "render", "--node", "relay")
	require.ErrorContains(t, err, "nodes/relay/reality", "relay's own key isn't on de")
}

func TestPlan_Flags(t *testing.T) {
	_, err := run(t, "--config", "../../testdata/fleet/princo.yaml", "plan")
	require.ErrorContains(t, err, "--node is required")
	_, err = run(t, "--config", "../../testdata/fleet/princo.yaml", "plan", "--node", "nope")
	require.ErrorContains(t, err, `no node named "nope"`)
	_, err = run(t, "--config", "../../testdata/fleet/princo.yaml", "render", "--user", "alice", "--out", "x")
	require.ErrorContains(t, err, "--out needs --node")
}
