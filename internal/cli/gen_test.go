package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/secrets"
)

// runIn runs princo against the fleet in dir, returning stdout and stderr.
func runIn(t *testing.T, dir string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs(append([]string{
		"--config", filepath.Join(dir, "princo.yaml"),
		"--key", filepath.Join(dir, "key.txt"),
	}, args...))
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func secretGet(t *testing.T, dir, path string) string {
	t.Helper()
	out, _, err := runIn(t, dir, "secret", "get", path)
	require.NoError(t, err, path)
	return strings.TrimSuffix(out, "\n")
}

func TestInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fleet")
	_, stderr, err := runIn(t, dir, "init")
	require.NoError(t, err)
	require.Contains(t, stderr, "key.txt: created")
	require.FileExists(t, filepath.Join(dir, "recipients"))

	out, _, err := runIn(t, dir, "secret", "list")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"nodes/nl/reality", "users/alice", "users/bob"},
		strings.Fields(out))

	data, err := os.ReadFile(filepath.Join(dir, "princo.yaml"))
	require.NoError(t, err)
	cfg, err := config.Parse(data)
	require.NoError(t, err)
	nl, _ := cfg.Nodes.Get("nl")
	require.Regexp(t, `^[A-Za-z0-9_-]{43}$`, nl.Reality.PublicKey)
	require.Regexp(t, `^[0-9a-f]{8}$`, nl.Reality.ShortID)

	_, _, err = runIn(t, dir, "plan", "--node", "nl")
	require.NoError(t, err)
	_, _, err = runIn(t, dir, "render", "--user", "alice")
	require.NoError(t, err)

	_, _, err = runIn(t, dir, "init")
	require.ErrorContains(t, err, "princo.yaml already exists")
}

func TestInit_KeepsRecipients(t *testing.T) {
	configPath, _, recipientsPath := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.Remove(configPath))
	before, err := os.ReadFile(recipientsPath)
	require.NoError(t, err)

	_, stderr, err := runIn(t, dir, "init")
	require.NoError(t, err)
	require.NotContains(t, stderr, "recipients: written")
	after, err := os.ReadFile(recipientsPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestSecretGen(t *testing.T) {
	configPath, _, _ := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.WriteFile(configPath, []byte(`princo: v1
nodes:
  fr:
    address: fr.example.com
    reality: { server_name: www.example.com, short_id: "01" }
    egress: warp
users:
  alice: {}
  bob: { uuid: 11111111-2222-4333-8444-555555555555 }
`), 0o644))

	_, stderr, err := runIn(t, dir, "secret", "gen")
	require.NoError(t, err)
	require.Contains(t, stderr, "nodes/fr/warp/private_key: missing; it comes from outside princo")
	require.Contains(t, stderr, "nodes.fr.reality.public_key: add it to princo.yaml: ")
	require.Regexp(t, `^[0-9a-f-]{36}$`, secretGet(t, dir, "users/alice"))
	require.NotEmpty(t, secretGet(t, dir, "nodes/fr/reality"))

	_, _, err = runIn(t, dir, "secret", "gen", "users/alice")
	require.ErrorContains(t, err, "users/alice: already has a value; pass --force")
	alice := secretGet(t, dir, "users/alice")
	_, _, err = runIn(t, dir, "secret", "gen", "--force", "users/alice")
	require.NoError(t, err)
	require.NotEqual(t, alice, secretGet(t, dir, "users/alice"))

	_, _, err = runIn(t, dir, "secret", "gen", "users/bob")
	require.ErrorContains(t, err, "princo.yaml doesn't use this secret")
	_, _, err = runIn(t, dir, "secret", "gen", "nodes/fr/warp/ipv4")
	require.ErrorContains(t, err, "comes from outside princo")
	_, _, err = runIn(t, dir, "secret", "gen", "--force")
	require.ErrorContains(t, err, "--force needs the paths")
}

func TestSecretSet_FollowsMappings(t *testing.T) {
	configPath, keyPath, _ := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.WriteFile(configPath, []byte("princo: v1\nsecrets:\n  users/*: age:users.age\n"), 0o644))

	cmd := NewRootCommand()
	cmd.SetIn(strings.NewReader("uuid-a\n"))
	cmd.SetArgs([]string{"--config", configPath, "--key", keyPath, "secret", "set", "users/alice"})
	require.NoError(t, cmd.Execute())
	require.FileExists(t, filepath.Join(dir, "users.age"))
	require.Equal(t, "uuid-a", secretGet(t, dir, "users/alice"))
}

func TestUser(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runIn(t, dir, "init")
	require.NoError(t, err)
	configPath := filepath.Join(dir, "princo.yaml")

	_, _, err = runIn(t, dir, "user", "add", "carol", "--nodes", "nl")
	require.NoError(t, err)
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "  bob: {}\n  carol: { nodes: [nl] }\n\nclient:\n")
	carol := secretGet(t, dir, "users/carol")

	_, _, err = runIn(t, dir, "user", "add", "carol")
	require.ErrorContains(t, err, "users.carol already exists")
	_, _, err = runIn(t, dir, "user", "add", "dave", "--nodes", "de")
	require.ErrorContains(t, err, `--nodes: no node named "de"`)
	_, _, err = runIn(t, dir, "user", "add", "Dave")
	require.ErrorContains(t, err, `user name "Dave"`)

	_, _, err = runIn(t, dir, "user", "rotate", "carol")
	require.NoError(t, err)
	require.NotEqual(t, carol, secretGet(t, dir, "users/carol"))
	_, _, err = runIn(t, dir, "user", "rotate", "zed")
	require.ErrorContains(t, err, `no user named "zed"`)

	_, _, err = runIn(t, dir, "user", "remove", "bob")
	require.NoError(t, err)
	out, _, err := runIn(t, dir, "secret", "list")
	require.NoError(t, err)
	require.NotContains(t, out, "users/bob")
	data, err = os.ReadFile(configPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "  alice: {}\n  carol: { nodes: [nl] }\n")
}

func TestInit_ReusesRealityKey(t *testing.T) {
	configPath, _, _ := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.Remove(configPath))
	private, public, err := secrets.NewRealityKeyPair()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, []byte("princo: v1\n"), 0o644))
	cmd := NewRootCommand()
	cmd.SetIn(strings.NewReader(private + "\n"))
	cmd.SetArgs([]string{"--config", configPath, "--key", filepath.Join(dir, "key.txt"), "secret", "set", "nodes/nl/reality"})
	require.NoError(t, cmd.Execute())
	require.NoError(t, os.Remove(configPath))

	_, _, err = runIn(t, dir, "init")
	require.NoError(t, err)
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	cfg, err := config.Parse(data)
	require.NoError(t, err)
	nl, _ := cfg.Nodes.Get("nl")
	require.Equal(t, public, nl.Reality.PublicKey)
	require.Equal(t, private, secretGet(t, dir, "nodes/nl/reality"))
}

func TestSecretGen_SharedRealityKey(t *testing.T) {
	configPath, _, _ := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.WriteFile(configPath, []byte(`princo: v1
nodes:
  a: { address: a.example.com, reality: { server_name: www.example.com, short_id: "01", public_key: x, private_key: !secret keys/r } }
  b: { address: b.example.com, reality: { server_name: www.example.com, short_id: "01", public_key: y, private_key: !secret keys/r } }
`), 0o644))
	_, _, err := runIn(t, dir, "secret", "gen", "keys/r")
	require.NoError(t, err)
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	cfg, err := config.Parse(data)
	require.NoError(t, err)
	a, _ := cfg.Nodes.Get("a")
	b, _ := cfg.Nodes.Get("b")
	require.NotEqual(t, "x", a.Reality.PublicKey)
	require.Equal(t, a.Reality.PublicKey, b.Reality.PublicKey)
}

func TestUserRemove_KeepsSecretStoredForAnother(t *testing.T) {
	configPath, _, _ := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.WriteFile(configPath, []byte(`princo: v1
users:
  alice: {}
  bob: { uuid: !secret "age:secrets.age#users/alice" }
`), 0o644))
	_, _, err := runIn(t, dir, "secret", "gen")
	require.NoError(t, err)
	_, stderr, err := runIn(t, dir, "user", "remove", "alice")
	require.NoError(t, err)
	require.Contains(t, stderr, "users/alice: kept, princo.yaml still uses it")
	require.NotEmpty(t, secretGet(t, dir, "users/alice"))
}

func TestSecretGen_KeepsKeyWhenPublicKeyCantBeSet(t *testing.T) {
	configPath, _, _ := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	cfg := `princo: v1
nodes:
  fr:
    address: fr.example.com
    reality:
      server_name: www.example.com
      short_id: "01"
      public_key: |-
        old
`
	require.NoError(t, os.WriteFile(configPath, []byte(cfg), 0o644))
	_, _, err := runIn(t, dir, "secret", "gen", "nodes/fr/reality")
	require.ErrorContains(t, err, "can't edit this value in place")
	has, _, err := runIn(t, dir, "secret", "list")
	require.NoError(t, err)
	require.NotContains(t, has, "nodes/fr/reality")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, cfg, string(data))
}

func TestUserAdd_RollsBackWithoutUUID(t *testing.T) {
	configPath, _, recipientsPath := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.WriteFile(configPath, []byte("princo: v1\nusers:\n  alice: { uuid: 11111111-2222-4333-8444-555555555555 }\n"), 0o644))
	require.NoError(t, os.Remove(recipientsPath))
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets.age")))
	before, err := os.ReadFile(configPath)
	require.NoError(t, err)

	_, _, err = runIn(t, dir, "user", "add", "bob")
	require.ErrorContains(t, err, "users.bob removed from princo.yaml again")
	after, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after))
}

func TestUserRotate_RefusesSharedUUID(t *testing.T) {
	configPath, _, _ := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.WriteFile(configPath, []byte(`princo: v1
users:
  alice: {}
  bob: { uuid: !secret users/alice }
`), 0o644))
	_, _, err := runIn(t, dir, "secret", "gen")
	require.NoError(t, err)
	alice := secretGet(t, dir, "users/alice")
	_, _, err = runIn(t, dir, "user", "rotate", "alice")
	require.ErrorContains(t, err, "users.bob.uuid reads the same UUID")
	require.Equal(t, alice, secretGet(t, dir, "users/alice"))
}

func TestInit_ChecksRecipients(t *testing.T) {
	configPath, keyPath, recipientsPath := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.Remove(configPath))

	own, err := os.ReadFile(recipientsPath)
	require.NoError(t, err)
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(recipientsPath, []byte("# "+string(own)+other.Recipient().String()+"\n"), 0o644))
	_, _, err = runIn(t, dir, "init")
	require.ErrorContains(t, err, "doesn't list the identity at")

	require.NoError(t, os.Remove(keyPath))
	_, _, err = runIn(t, dir, "init")
	require.ErrorContains(t, err, "no age identity to read secrets")
	require.NoFileExists(t, configPath)
}

func TestUserRemove_KeepsUserWhenUUIDStays(t *testing.T) {
	configPath, _, recipientsPath := newSecretFixture(t)
	dir := filepath.Dir(configPath)
	require.NoError(t, os.WriteFile(configPath, []byte("princo: v1\nusers:\n  alice: {}\n"), 0o644))
	_, _, err := runIn(t, dir, "secret", "gen")
	require.NoError(t, err)
	require.NoError(t, os.Remove(recipientsPath))

	_, _, err = runIn(t, dir, "user", "remove", "alice")
	require.ErrorContains(t, err, "recipients")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "alice: {}")
	require.NotEmpty(t, secretGet(t, dir, "users/alice"))
}
