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

func TestInstallReleases(t *testing.T) {
	archives := map[string][]byte{
		"/xray.zip":        zipOf(t, "xray", "geoip.dat"),
		"/sing-box.tar.gz": tarGzOf(t, "sing-box-1.14.3-linux-amd64/sing-box", "sing-box-1.14.3-linux-amd64/libcronet.so"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archives[r.URL.Path])
	}))
	t.Cleanup(srv.Close)
	withRelease(t, "xray", srv.URL+"/xray.zip", archives["/xray.zip"])
	withRelease(t, "sing-box", srv.URL+"/sing-box.tar.gz", archives["/sing-box.tar.gz"])

	dir := t.TempDir()
	require.NoError(t, InstallReleases(t.Context(), srv.Client(), "amd64", dir))
	for _, name := range []string{"xray", "geoip.dat", "sing-box", "libcronet.so"} {
		_, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err, "the whole release, %s too", name)
	}
	require.ErrorContains(t, InstallReleases(t.Context(), srv.Client(), "riscv64", dir), "there's no sing-box for riscv64")

	sums, err := ReleaseDigests(t.Context(), srv.Client(), "xray", "26.9.9")
	require.NoError(t, err)
	sum := sha256.Sum256(archives["/xray.zip"])
	require.Equal(t, map[string]string{"amd64": hex.EncodeToString(sum[:])}, sums)
}

func TestReleaseURL(t *testing.T) {
	a, ok := engines["xray"].archive("arm64")
	require.True(t, ok)
	require.Equal(t, "https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-arm64-v8a.zip", a.URL)
	a, _ = engines["sing-box"].archive("amd64")
	require.Equal(t, "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz", a.URL)
}
