package deploy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// As ssh, the test binary forwards -W host:port to it over stdin and
// stdout, as ssh does from the host it logs in to.
func init() {
	if os.Getenv("PRINCO_FAKE_SSH") != "1" {
		return
	}
	args := os.Args[1:]
	for i, a := range args {
		if a == "-W" && i+1 < len(args) {
			c, err := net.Dial("tcp", args[i+1])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(255)
			}
			go func() { _, _ = io.Copy(c, os.Stdin); _ = c.(*net.TCPConn).CloseWrite() }()
			_, _ = io.Copy(os.Stdout, c)
			os.Exit(0)
		}
	}
	os.Exit(0) // the control master and -O exit
}

func TestSSH_Dial(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	bin := t.TempDir()
	require.NoError(t, os.Symlink(exe, filepath.Join(bin, "ssh")))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PRINCO_FAKE_SSH", "1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	}))
	defer srv.Close()

	s := &SSH{Target: "node.example.com", Stderr: io.Discard}
	require.NoError(t, s.Open(t.Context()))
	defer func() { _ = s.Close() }()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return s.Dial(ctx, srv.Listener.Addr().String())
		},
	}}
	for _, p := range []string{"/a", "/b"} {
		resp, err := client.Get("http://" + srv.Listener.Addr().String() + p)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, "hello "+p, string(body))
	}
	client.CloseIdleConnections()
}
