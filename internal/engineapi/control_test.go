package engineapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func outboundsMsg(tests map[string]outboundTest) []byte {
	var b []byte
	for _, tag := range []string{"direct", "warp"} {
		t, ok := tests[tag]
		if !ok {
			continue
		}
		item := appendBytesField(nil, 1, []byte(tag))
		if t.at != 0 {
			item = appendVarintField(item, 3, uint64(t.at))
			item = appendVarintField(item, 4, uint64(t.delay.Milliseconds()))
		}
		b = appendBytesField(b, 1, item)
	}
	return b
}

// An engine whose tests of warp end as results says, one per URLTest.
func testServer(t *testing.T, results ...outboundTest) *Client {
	var mu sync.Mutex
	tests := map[string]outboundTest{"direct": {}, "warp": {at: 100, delay: 80 * time.Millisecond}}
	updated := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		send := func() {
			mu.Lock()
			defer mu.Unlock()
			_, _ = w.Write(frame(0, outboundsMsg(tests)))
			w.(http.Flusher).Flush()
		}
		switch r.URL.Path {
		case "/daemon.StartedService/SubscribeOutbounds":
			send()
			select {
			case <-updated:
				send()
			case <-r.Context().Done():
			}
		case "/daemon.StartedService/URLTest":
			require.Equal(t, frame(0, appendBytesField(nil, 1, []byte("warp"))), body)
			mu.Lock()
			if len(results) > 0 {
				tests["warp"], results = results[0], results[1:]
				select {
				case updated <- struct{}{}:
				default:
				}
			}
			mu.Unlock()
			_, _ = w.Write(frame(0, nil))
			_, _ = w.Write(frame(0x80, []byte("grpc-status: 0\r\n")))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{HTTP: srv.Client(), URL: srv.URL}
}

func TestTestOutbound(t *testing.T) {
	client := testServer(t,
		outboundTest{at: 160, delay: 95 * time.Millisecond}, // answered
		outboundTest{}, // failed: the engine forgets the last answer
	)
	delay, err := client.TestOutbound(t.Context(), "warp")
	require.NoError(t, err)
	require.Equal(t, 95*time.Millisecond, delay)

	_, err = client.TestOutbound(t.Context(), "warp")
	require.ErrorIs(t, err, ErrTestFailed)

	// A test the engine doesn't end in time: its answer before isn't one.
	client = testServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, err = client.TestOutbound(ctx, "warp")
	require.ErrorIs(t, err, ErrTestFailed)

	_, err = client.TestOutbound(t.Context(), "gone")
	require.ErrorContains(t, err, "no outbound gone")
}

// Against sing-box itself, when it's in PATH: the engine lists the WARP
// endpoint among what it can test.
func TestOutbounds_SingBox(t *testing.T) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("no sing-box in PATH")
	}
	apiPort := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"endpoints": []any{map[string]any{
			"type": "wireguard", "tag": "warp", "address": []any{"172.16.0.2/32"},
			// Synthetic keys; nothing answers at the peer.
			"private_key": "YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04=",
			"peers": []any{map[string]any{
				"address": "127.0.0.1", "port": freePort(t), "allowed_ips": []any{"0.0.0.0/0"},
				"public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=",
			}},
		}},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"services": []any{map[string]any{
			"type": "api", "tag": "api", "listen": "127.0.0.1", "listen_port": apiPort, "secret": "s3cret",
		}},
		"route": map[string]any{"final": "warp"},
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	cmd := exec.CommandContext(t.Context(), bin, "run", "-c", path, "-D", t.TempDir())
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	client := &Client{HTTP: http.DefaultClient, URL: "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)), Secret: "s3cret"}
	var tests map[string]outboundTest
	require.Eventually(t, func() bool {
		return client.outbounds(t.Context(), func(got map[string]outboundTest) error {
			tests = got
			return ErrStop
		}) == nil
	}, 10*time.Second, 50*time.Millisecond)
	require.Contains(t, tests, "warp")
	require.Contains(t, tests, "direct")
}
