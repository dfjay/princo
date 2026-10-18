package secrets

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeResolver resolves against in-memory files keyed by "kind:path".
func fakeResolver(t *testing.T, mappings []Mapping, files map[string]map[string]any) (*Resolver, *[]string) {
	t.Helper()
	r, err := NewResolver("/fleet", "/key.txt", mappings)
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
		{"users/*", "sops:../secrets/shared.yaml#vless_uuid_*"},
		{"shared/hy2_obfs", "sops:../secrets/shared.yaml#hy2_obfs_password"},
		{"nodes/fr/reality", "sops:../secrets/gandi.yaml#reality_private_key"},
		{"nodes/fr/warp/*", "sops:../secrets/gandi.yaml#warp_*"},
		{"nodes/us/*", "sops:../secrets/linode.yaml"},
	}, map[string]map[string]any{
		"sops:/secrets/shared.yaml": {"vless_uuid_alice": "uuid-a", "hy2_obfs_password": "obfs"},
		"sops:/secrets/gandi.yaml":  {"reality_private_key": "rk", "warp_ipv4": "10.0.0.2/32", "warp_mtu": 1280},
		"sops:/secrets/linode.yaml": {"reality": "rk-us"},
		"age:/fleet/secrets.age":    {"nodes": map[string]any{"de": map[string]any{"chain": "c"}}},
	})

	for path, want := range map[string]string{
		"users/alice":        "uuid-a",
		"shared/hy2_obfs":    "obfs",
		"nodes/fr/reality":   "rk",
		"nodes/fr/warp/ipv4": "10.0.0.2/32",
		"nodes/fr/warp/mtu":  "1280",
		"nodes/us/reality":   "rk-us",
		"nodes/de/chain":     "c", // no mapping: default age file
		"sops:../secrets/shared.yaml#vless_uuid_alice": "uuid-a", // explicit location
	} {
		got, err := r.Get(path)
		require.NoError(t, err, path)
		require.Equal(t, want, got, path)
	}
	require.Len(t, *opened, 4, "each file is decrypted once")
}

func TestResolver_Errors(t *testing.T) {
	r, _ := fakeResolver(t, []Mapping{{"users/*", "sops:s.yaml#vless_uuid_*"}},
		map[string]map[string]any{"sops:/fleet/s.yaml": {"vless_uuid_alice": "x"}})
	_, err := r.Get("users/bob")
	require.ErrorContains(t, err, "users/bob (looked up as sops:s.yaml#vless_uuid_bob): secret not found")

	_, err = NewResolver("/", "", []Mapping{{"a/*/b", "sops:x"}})
	require.ErrorContains(t, err, "only allowed at the end")
	_, err = NewResolver("/", "", []Mapping{{"a", "vault:x"}})
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

	r, err := NewResolver(dir, "", []Mapping{{"users/*", "sops:shared.yaml#vless_uuid_*"}})
	require.NoError(t, err)
	got, err := r.Get("users/alice")
	require.NoError(t, err)
	require.Equal(t, "uuid-a", got)
}
