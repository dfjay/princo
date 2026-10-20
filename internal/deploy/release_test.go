package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeCosign puts a cosign on PATH that exits with code.
func fakeCosign(t *testing.T, code string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'cosign says no' >&2\nexit " + code + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cosign"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func releaseServer(t *testing.T, deb []byte, sumOf []byte) string {
	t.Helper()
	sum := sha256.Sum256(sumOf)
	files := map[string][]byte{
		"/v0.2.0/checksums.txt":               []byte(hex.EncodeToString(sum[:]) + "  princo_0.2.0_arm64.deb\n"),
		"/v0.2.0/checksums.txt.sigstore.json": []byte("{}"),
		"/v0.2.0/princo_0.2.0_arm64.deb":      deb,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestReleaseDeb(t *testing.T) {
	fakeCosign(t, "0")
	url := releaseServer(t, []byte("deb"), []byte("deb"))
	deb, err := ReleaseDeb(t.Context(), http.DefaultClient, url, "0.2.0", "arm64")
	require.NoError(t, err)
	require.Equal(t, "deb", string(deb))

	_, err = ReleaseDeb(t.Context(), http.DefaultClient, url, "0.2.0", "amd64")
	require.ErrorContains(t, err, "princo 0.2.0 has no princo_0.2.0_amd64.deb")
}

func TestReleaseDeb_Tampered(t *testing.T) {
	fakeCosign(t, "0")
	url := releaseServer(t, []byte("evil"), []byte("deb"))
	_, err := ReleaseDeb(t.Context(), http.DefaultClient, url, "0.2.0", "arm64")
	require.ErrorContains(t, err, "princo_0.2.0_arm64.deb doesn't match princo 0.2.0's checksums.txt")
}

func TestReleaseDeb_BadSignature(t *testing.T) {
	fakeCosign(t, "1")
	url := releaseServer(t, []byte("deb"), []byte("deb"))
	_, err := ReleaseDeb(t.Context(), http.DefaultClient, url, "0.2.0", "arm64")
	require.ErrorContains(t, err, "checksums.txt fails verification")
	require.ErrorContains(t, err, "cosign says no")
}

func TestReleaseDeb_NoCosign(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := ReleaseDeb(t.Context(), http.DefaultClient, "http://unused", "0.2.0", "arm64")
	require.ErrorContains(t, err, "cosign is needed")
}
