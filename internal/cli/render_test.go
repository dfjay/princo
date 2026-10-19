package cli

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dfjay/princo/internal/secrets"
)

// fixtureDir copies the fixture fleet into a temp dir with its secrets
// encrypted under a fresh age identity; returns the config and key paths.
func fixtureDir(t *testing.T) (configPath, keyPath string) {
	t.Helper()
	src := "../../testdata/fleet"
	tmp := t.TempDir()

	data, err := os.ReadFile(filepath.Join(src, "princo.yaml"))
	require.NoError(t, err)
	configPath = filepath.Join(tmp, "princo.yaml")
	require.NoError(t, os.WriteFile(configPath, data, 0o644))

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyPath = filepath.Join(tmp, "key.txt")
	require.NoError(t, os.WriteFile(keyPath, []byte(identity.String()+"\n"), 0o600))
	recipients := filepath.Join(tmp, "recipients")
	require.NoError(t, os.WriteFile(recipients, []byte(identity.Recipient().String()+"\n"), 0o644))

	plain, err := os.ReadFile(filepath.Join(src, "secrets.test.yaml"))
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, yaml.Unmarshal(plain, &values))
	require.NoError(t, secrets.Save(filepath.Join(tmp, "secrets.age"), recipients, values))
	return configPath, keyPath
}

func runRender(t *testing.T, args ...string) (string, error) {
	t.Helper()
	configPath, keyPath := fixtureDir(t)
	var stdout bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&stdout)
	cmd.SetArgs(append([]string{"--config", configPath, "--key", keyPath, "render"}, args...))
	err := cmd.Execute()
	return stdout.String(), err
}

func TestRender_MatchesGolden(t *testing.T) {
	for args, golden := range map[string]string{
		"--node de":    "server-de.json",
		"--user alice": "client-alice.json",
	} {
		t.Run(args, func(t *testing.T) {
			out, err := runRender(t, splitArgs(args)...)
			require.NoError(t, err)
			want, err := os.ReadFile(filepath.Join("../../testdata/fleet/golden", golden))
			require.NoError(t, err)
			require.JSONEq(t, string(want), out)
		})
	}
}

func TestRender_URIs(t *testing.T) {
	out, err := runRender(t, "--user", "bob", "--uris")
	require.NoError(t, err)
	require.Contains(t, out, "#bob-us-reality\n")
	require.Contains(t, out, "#bob-relay-reality\n")
}

func TestRender_Links(t *testing.T) {
	out, err := runRender(t, "--user", "alice", "--links")
	require.NoError(t, err)
	// The token is what `sops decrypt ... | sha256sum | cut -c1-32` gave
	// before princo, so users keep their links.
	const sub = "https://subs.example.com/f8cb68efcef124689abd331ff3fa5241/"
	require.Equal(t, "QR page:   "+sub+"qr\n"+
		"Universal: "+sub+"\n"+
		"sing-box:  sing-box://import-remote-profile?url="+url.QueryEscape(sub+"sing-box")+"#alice\n", out)
}

func TestRender_LinksMissingUUID(t *testing.T) {
	_, err := run(t, "--config", "../../testdata/fleet/princo.yaml", "--secrets-dir", t.TempDir(),
		"render", "--user", "alice", "--links")
	require.ErrorContains(t, err, "secrets missing from")
	require.ErrorContains(t, err, "users/alice")
}

func TestRender_Flags(t *testing.T) {
	_, err := runRender(t)
	require.ErrorContains(t, err, "exactly one of --node or --user")
	_, err = runRender(t, "--node", "de", "--uris")
	require.ErrorContains(t, err, "--uris and --links need --user")
	_, err = runRender(t, "--user", "alice", "--uris", "--links")
	require.ErrorContains(t, err, "at most one of --uris or --links")
	_, err = runRender(t, "--node", "nope")
	require.ErrorContains(t, err, `no node named "nope"`)
}

func splitArgs(s string) []string {
	var out []string
	for f := range bytes.FieldsSeq([]byte(s)) {
		out = append(out, string(f))
	}
	return out
}
