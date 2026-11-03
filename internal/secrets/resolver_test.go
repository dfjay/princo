package secrets

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

// fakeResolver resolves against in-memory files keyed by "kind:path".
func fakeResolver(t *testing.T, mappings []Mapping, files map[string]map[string]any) (*Resolver, *[]string) {
	t.Helper()
	r, err := NewResolver([]string{"/fleet"}, "/key.txt", mappings)
	require.NoError(t, err)
	var opened []string
	r.decrypt = func(kind, path, _ string) (map[string]any, error) {
		opened = append(opened, kind+":"+path)
		v, ok := files[kind+":"+path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return v, nil
	}
	return r, &opened
}

func TestResolver_Mappings(t *testing.T) {
	r, opened := fakeResolver(t, []Mapping{
		{Pattern: "users/*", Target: "sops:../secrets/shared.yaml#vless_uuid_*"},
		{Pattern: "shared/hysteria2_obfs", Target: "sops:../secrets/shared.yaml#hysteria2_obfs_password"},
		{Pattern: "nodes/fr/reality", Target: "sops:../secrets/gandi.yaml#reality_private_key"},
		{Pattern: "nodes/fr/warp/*", Target: "sops:../secrets/gandi.yaml#warp_*"},
		{Pattern: "nodes/us/*", Target: "sops:../secrets/linode.yaml"},
	}, map[string]map[string]any{
		"sops:/secrets/shared.yaml": {"vless_uuid_alice": "uuid-a", "hysteria2_obfs_password": "obfs"},
		"sops:/secrets/gandi.yaml":  {"reality_private_key": "rk", "warp_ipv4": "10.0.0.2/32", "warp_mtu": 1280},
		"sops:/secrets/linode.yaml": {"reality": "rk-us"},
		"age:/fleet/secrets.age":    {"nodes": map[string]any{"de": map[string]any{"chain": "c"}}},
	})

	for path, want := range map[string]string{
		"users/alice":           "uuid-a",
		"shared/hysteria2_obfs": "obfs",
		"nodes/fr/reality":      "rk",
		"nodes/fr/warp/ipv4":    "10.0.0.2/32",
		"nodes/fr/warp/mtu":     "1280",
		"nodes/us/reality":      "rk-us",
		"nodes/de/chain":        "c", // no mapping: default age file
	} {
		got, err := r.Get(path)
		require.NoError(t, err, path)
		require.Equal(t, want, got, path)
	}
	require.Len(t, *opened, 4, "each file is decrypted once")
}

func TestResolver_Errors(t *testing.T) {
	r, _ := fakeResolver(t, []Mapping{{Pattern: "users/*", Target: "sops:s.yaml#vless_uuid_*"}},
		map[string]map[string]any{"sops:/fleet/s.yaml": {"vless_uuid_alice": "x"}})
	_, err := r.Get("users/bob")
	require.ErrorContains(t, err, "users/bob (looked up as sops:s.yaml#vless_uuid_bob): secret not found")

	_, err = NewResolver([]string{"/"}, "", []Mapping{{Pattern: "a/*/b", Target: "sops:x"}})
	require.ErrorContains(t, err, "only allowed at the end")
	_, err = NewResolver([]string{"/"}, "", []Mapping{{Pattern: "a", Target: "vault:x"}})
	require.ErrorContains(t, err, "want sops:<file>")
}

// TestResolver_RealSops encrypts a file with the sops CLI and an age key,
// then resolves through it; skipped without sops and age-keygen.
func TestResolver_RealSops(t *testing.T) {
	sops, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops not in PATH")
	}
	keygen, err := exec.LookPath("age-keygen")
	if err != nil {
		t.Skip("age-keygen not in PATH")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.txt")
	out, err := exec.Command(keygen, "-o", keyFile).CombinedOutput()
	require.NoError(t, err, string(out))
	pub, err := exec.Command(keygen, "-y", keyFile).Output()
	require.NoError(t, err)

	plain := filepath.Join(dir, "shared.yaml")
	require.NoError(t, os.WriteFile(plain, []byte("vless_uuid_alice: uuid-a\n"), 0o600))
	enc, err := exec.Command(sops, "--encrypt", "--age", string(pub[:len(pub)-1]), "--in-place", plain).CombinedOutput()
	require.NoError(t, err, string(enc))
	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

	r, err := NewResolver([]string{dir}, "", []Mapping{{Pattern: "users/*", Target: "sops:shared.yaml#vless_uuid_*"}})
	require.NoError(t, err)
	got, err := r.Get("users/alice")
	require.NoError(t, err)
	require.Equal(t, "uuid-a", got)

	require.NoError(t, r.Set("users/bob", "uuid-b"))
	require.NoError(t, r.Delete("users/alice"))
	got, err = r.Get("users/bob")
	require.NoError(t, err)
	require.Equal(t, "uuid-b", got)
	_, err = r.Get("users/alice")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestResolver_SetAge(t *testing.T) {
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "key.txt")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))
	recipients := filepath.Join(dir, "recipients")
	require.NoError(t, os.WriteFile(recipients, []byte(id.Recipient().String()+"\n"), 0o644))

	r, err := NewResolver([]string{dir}, keyFile, []Mapping{{Pattern: "nodes/fr/*", Target: "age:fr.age"}})
	require.NoError(t, err)
	require.ErrorContains(t, r.Set("users/alice", "a"), "no recipients file")
	r.Recipients = recipients
	has, err := r.Has("users/alice")
	require.NoError(t, err)
	require.False(t, has, "no secrets.age yet")

	require.NoError(t, r.Set("users/alice", "a"))
	require.NoError(t, r.Set("users/bob", "b"))
	require.NoError(t, r.Set("nodes/fr/reality", "rk"))
	require.NoError(t, r.Delete("users/bob"))

	r, err = NewResolver([]string{dir}, keyFile, []Mapping{{Pattern: "nodes/fr/*", Target: "age:fr.age"}})
	require.NoError(t, err)
	for path, want := range map[string]string{"users/alice": "a", "nodes/fr/reality": "rk"} {
		got, err := r.Get(path)
		require.NoError(t, err, path)
		require.Equal(t, want, got)
	}
	has, err = r.Has("users/bob")
	require.NoError(t, err)
	require.False(t, has)
	fr, err := Open(filepath.Join(dir, "fr.age"), keyFile)
	require.NoError(t, err)
	require.Equal(t, []string{"reality"}, fr.List())
}

func TestResolver_SetRefusesForeignRecipients(t *testing.T) {
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "key.txt")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))
	recipients := filepath.Join(dir, "recipients")
	require.NoError(t, os.WriteFile(recipients, []byte("# "+id.Recipient().String()+"\n"+other.Recipient().String()+"\n"), 0o644))

	r, err := NewResolver([]string{dir}, keyFile, nil)
	require.NoError(t, err)
	r.Recipients = recipients
	require.ErrorContains(t, r.Set("users/alice", "a"), "doesn't list the identity at")
	require.NoFileExists(t, filepath.Join(dir, DefaultFile))

	require.NoError(t, os.WriteFile(recipients, []byte(other.Recipient().String()+"\n"+id.Recipient().String()+"\n"), 0o644))
	require.NoError(t, r.Set("users/alice", "a"))
}

func TestCheckRecipients_Hybrid(t *testing.T) {
	dir := t.TempDir()
	id, err := age.GenerateHybridIdentity()
	require.NoError(t, err)
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "key.txt")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))
	recipients := filepath.Join(dir, "recipients")
	require.NoError(t, os.WriteFile(recipients, []byte(other.Recipient().String()+"\n"), 0o644))
	require.ErrorContains(t, CheckRecipients(keyFile, recipients), "doesn't list the identity at")
	require.NoError(t, os.WriteFile(recipients, []byte(id.Recipient().String()+"\n"), 0o644))
	require.NoError(t, CheckRecipients(keyFile, recipients))
}

func TestResolver_FilesRelativeToTheirConfig(t *testing.T) {
	r, err := NewResolver([]string{"/pub", "/priv"}, "", []Mapping{
		{Pattern: "users/*", Target: "sops:shared.yaml#uuid_*", File: 1},
		{Pattern: "nodes/*", Target: "sops:nodes.yaml", File: 0},
	})
	require.NoError(t, err)
	var opened []string
	r.decrypt = func(kind, path, _ string) (map[string]any, error) {
		opened = append(opened, kind+":"+path)
		return map[string]any{"uuid_alice": "a", "fr": "f", "k": "v"}, nil
	}

	for path, want := range map[string]struct {
		location string
		file     int
	}{
		"users/alice":           {"sops:shared.yaml#uuid_alice", 1},
		"nodes/fr":              {"sops:nodes.yaml#fr", 0},
		"shared/hysteria2_obfs": {"age:secrets.age#shared/hysteria2_obfs", 1},
	} {
		location, file := r.Where(path)
		require.Equal(t, want.location, location, path)
		require.Equal(t, want.file, file, path)
	}

	for _, path := range []string{"users/alice", "nodes/fr"} {
		_, err := r.Get(path)
		require.NoError(t, err, path)
	}
	require.Equal(t, []string{
		"sops:/priv/shared.yaml",
		"sops:/pub/nodes.yaml",
	}, opened)

	_, err = NewResolver([]string{"/pub"}, "", []Mapping{{Pattern: "a", Target: "sops:x", File: 1}})
	require.ErrorContains(t, err, "config file 1 of 1")
	_, err = NewResolver(nil, "", nil)
	require.Error(t, err)
}

func TestResolver_Identity(t *testing.T) {
	r, err := NewResolver([]string{"/pub", "/priv", "/priv"}, "", []Mapping{
		{Pattern: "users/*", Target: "sops:shared.yaml#uuid_*", File: 0},
		{Pattern: "chains/*", Target: "sops:shared.yaml#uuid_*", File: 2},
	})
	require.NoError(t, err)

	require.Equal(t, r.Locate("users/bob"), r.Locate("chains/bob"))
	require.Equal(t, "sops:/pub/shared.yaml#uuid_bob", r.Identity("users/bob"))
	require.Equal(t, "sops:/priv/shared.yaml#uuid_bob", r.Identity("chains/bob"))
}

func TestResolver_IdentityOfRelativeDirs(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	r, err := NewResolver([]string{".", wd}, "", []Mapping{
		{Pattern: "a", Target: "age:shared.age#s", File: 0},
		{Pattern: "b", Target: "age:shared.age#s", File: 1},
	})
	require.NoError(t, err)
	require.Equal(t, r.Identity("a"), r.Identity("b"))
}

func TestResolver_MostSpecificMappingWins(t *testing.T) {
	// A public file's mappings come first, as merged.
	r, err := NewResolver([]string{"/pub", "/priv"}, "", []Mapping{
		{Pattern: "users/*", Target: "sops:shared.yaml#uuid_*", File: 0},
		{Pattern: "nodes/*", Target: "sops:nodes.yaml", File: 0},
		{Pattern: "users/bob", Target: "sops:bob.yaml#uuid", File: 1},
		{Pattern: "nodes/fr/*", Target: "sops:fr.yaml", File: 1},
	})
	require.NoError(t, err)
	for path, want := range map[string]string{
		"users/alice":      "sops:shared.yaml#uuid_alice",
		"users/bob":        "sops:bob.yaml#uuid",
		"nodes/us/reality": "sops:nodes.yaml#us/reality",
		"nodes/fr/reality": "sops:fr.yaml#reality",
	} {
		require.Equal(t, want, r.Locate(path), path)
	}
}

func TestResolver_TakesPathsOnly(t *testing.T) {
	r, err := NewResolver([]string{"/fleet"}, "", nil)
	require.NoError(t, err)
	_, err = r.Get("sops:s.yaml#k")
	require.ErrorContains(t, err, "a storage location, not a secret path")
	require.ErrorContains(t, r.Set("age:x#k", "v"), "a storage location")
	for _, bad := range []string{"users//alice", "/users/alice", "users/", "../users/alice", "users/./alice", "users/a.b", "users/a b", "users/a\nb", ""} {
		_, err = r.Get(bad)
		require.ErrorContains(t, err, "want parts of letters", "%q", bad)
	}
}

func TestResolver_IdentityCleansAbsolutePaths(t *testing.T) {
	r, err := NewResolver([]string{"/fleet"}, "", []Mapping{
		{Pattern: "users/*", Target: "age:/fleet/old/../shared.age#x/*"},
		{Pattern: "nodes/*", Target: "age:shared.age#x/*"},
	})
	require.NoError(t, err)
	require.Equal(t, r.Identity("users/alice"), r.Identity("nodes/alice"))
}
