package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSplitConfig splits a fleet as public dotfiles would: what it runs
// in one file, where it runs and its secrets in another.
func TestSplitConfig(t *testing.T) {
	private, keyPath, _ := newSecretFixture(t)
	priv := filepath.Dir(private)
	pub := filepath.Join(t.TempDir(), "princo.yaml")
	base := `princo: v1
defaults:
  reality: { server_name: www.example.com }
  egress: direct
nodes:
  fr:
    hysteria2: { obfs: salamander }
    reality: { public_key: overridden }
secrets:
  shared/*: age:shared.age
users:
  alice: {}
`
	require.NoError(t, os.WriteFile(pub, []byte(base), 0o644))
	require.NoError(t, os.WriteFile(private, []byte(`princo: v1
nodes:
  fr:
    address: fr.example.com
    reality: { short_id: "01", public_key: unset }
secrets:
  nodes/*: age:nodes.age
`), 0o644))

	princo := func(args ...string) (string, string, error) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		cmd := NewRootCommand()
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetIn(strings.NewReader(""))
		cmd.SetArgs(append([]string{"--config", pub, "--config", private, "--key", keyPath}, args...))
		err := cmd.Execute()
		return stdout.String(), stderr.String(), err
	}

	_, stderr, err := princo("secret", "gen")
	require.NoError(t, err)
	require.Contains(t, stderr, "nodes.fr.reality.public_key: updated in princo.yaml")
	require.FileExists(t, filepath.Join(priv, "nodes.age"))
	require.FileExists(t, filepath.Join(priv, "secrets.age"))
	require.NoFileExists(t, filepath.Join(filepath.Dir(pub), "secrets.age"))
	data, err := os.ReadFile(private)
	require.NoError(t, err)
	require.NotContains(t, string(data), "unset")
	data, err = os.ReadFile(pub)
	require.NoError(t, err)
	require.Equal(t, base, string(data), "the key goes only where the merged value comes from")

	_, _, err = princo("user", "add", "carol")
	require.NoError(t, err)
	data, err = os.ReadFile(private)
	require.NoError(t, err)
	require.Contains(t, string(data), "users:\n  carol: {}\n")
	_, _, err = princo("user", "add", "alice")
	require.ErrorContains(t, err, "users.alice already exists")

	out, _, err := princo("plan", "--node", "fr")
	require.NoError(t, err)
	var plan struct {
		Secrets []struct {
			Path   string
			Source struct {
				Type   string
				File   string
				Config int
			}
		}
	}
	require.NoError(t, json.Unmarshal([]byte(out), &plan))
	files := map[string]string{}
	for _, s := range plan.Secrets {
		files[s.Path] = s.Source.File + "@" + string(rune('0'+s.Source.Config))
	}
	require.Equal(t, map[string]string{
		"nodes/fr/reality":      "nodes.age@1",
		"shared/hysteria2_obfs": "shared.age@0",
		"users/alice":           "secrets.age@1",
		"users/carol":           "secrets.age@1",
	}, files)

	// carol is the private file's only user: an emptied users: there must
	// not drop the base's users.
	_, _, err = princo("user", "remove", "carol")
	require.NoError(t, err)
	data, err = os.ReadFile(private)
	require.NoError(t, err)
	require.NotContains(t, string(data), "users:")
	out, _, err = princo("render", "--user", "alice", "--uris")
	require.NoError(t, err)
	require.NotEmpty(t, out)

	out, _, err = princo("secret", "list", "--check")
	require.NoError(t, err)
	require.Regexp(t, `shared/hysteria2_obfs\s+age:shared.age#hysteria2_obfs\s+`+regexp.QuoteMeta(pub)+`\s+set`, out)
	require.Regexp(t, `nodes/fr/reality\s+age:nodes.age#fr/reality\s+`+regexp.QuoteMeta(private)+`\s+set`, out)

	_, _, err = princo("user", "remove", "alice")
	require.NoError(t, err)
	data, err = os.ReadFile(pub)
	require.NoError(t, err)
	require.Equal(t, strings.Replace(base, "users:\n  alice: {}\n", "", 1), string(data))

	_, _, err = princo("init")
	require.ErrorContains(t, err, "init writes one file")
}

func TestConfigFilesSave_AllOrNone(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "locked", "b.yaml")
	require.NoError(t, os.Mkdir(filepath.Dir(b), 0o755))
	require.NoError(t, os.WriteFile(a, []byte("princo: v1\n"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("princo: v1\n"), 0o644))
	files, err := readConfigFiles(&globalFlags{ConfigPaths: []string{a, b}})
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(filepath.Dir(b)))
	edited := files.with(0, []byte("princo: v1\nusers: { x: {} }\n")).with(1, []byte("princo: v1\nusers: { y: {} }\n"))
	require.Error(t, edited.save(files))

	data, err := os.ReadFile(a)
	require.NoError(t, err)
	require.Equal(t, "princo: v1\n", string(data))
	leftovers, err := filepath.Glob(filepath.Join(dir, ".princo.yaml.*"))
	require.NoError(t, err)
	require.Empty(t, leftovers)
}

func TestConfigFilesSave_RestoresOnFailedReplace(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")
	require.NoError(t, os.WriteFile(a, []byte("princo: v1\n"), 0o644))
	files := &configFiles{paths: []string{a, b}, data: [][]byte{[]byte("princo: v1\n"), []byte("princo: v1\n")}}
	// A directory where b was: staging works, replacing it doesn't.
	require.NoError(t, os.MkdirAll(filepath.Join(b, "x"), 0o755))

	edited := files.with(0, []byte("princo: v1\nusers: { x: {} }\n")).with(1, []byte("princo: v1\nusers: { y: {} }\n"))
	require.Error(t, edited.save(files))
	data, err := os.ReadFile(a)
	require.NoError(t, err)
	require.Equal(t, "princo: v1\n", string(data))
}

// TestSecretGen_RefusesPublicKeyFromMergeKey: princo can't edit a public
// key a merge key supplies, so it mustn't replace the private key either.
func TestSecretGen_RefusesPublicKeyFromMergeKey(t *testing.T) {
	private, keyPath, _ := newSecretFixture(t)
	pub := filepath.Join(t.TempDir(), "princo.yaml")
	base := "princo: v1\nnodes:\n  fr: { address: fr.example.com, reality: { server_name: www.example.com, short_id: \"01\", public_key: base } }\n"
	over := "princo: v1\nnodes:\n  fr: { reality: { <<: { public_key: merged } } }\n"
	require.NoError(t, os.WriteFile(pub, []byte(base), 0o644))
	require.NoError(t, os.WriteFile(private, []byte(over), 0o644))

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--config", pub, "--config", private, "--key", keyPath, "secret", "gen", "nodes/fr/reality"})
	require.ErrorContains(t, cmd.Execute(), "nodes.fr.reality.public_key: can't set it where its value comes from")

	for path, want := range map[string]string{pub: base, private: over} {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, want, string(data))
	}
	_, _, err := runIn(t, filepath.Dir(private), "secret", "get", "nodes/fr/reality")
	require.Error(t, err, "no private key was stored")
}

func TestConfigFilesSave_FollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target.yaml"), filepath.Join(dir, "princo.yaml")
	require.NoError(t, os.WriteFile(target, []byte("princo: v1\n"), 0o644))
	require.NoError(t, os.Symlink(target, link))
	files, err := readConfigFiles(&globalFlags{ConfigPaths: []string{link}})
	require.NoError(t, err)

	edited := []byte("princo: v1\nusers: { x: {} }\n")
	require.NoError(t, files.with(0, edited).save(files))
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, string(edited), string(data))
	info, err := os.Lstat(link)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
}
