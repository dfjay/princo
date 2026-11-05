package stats

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The fields of the messages, as sing-box encodes them.

func bytesField(b []byte, num int, v []byte) []byte {
	b = appendVarint(b, uint64(num)<<3|wireBytes)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func connMsg(c Conn, source string) []byte {
	var b []byte
	b = bytesField(b, 1, []byte(c.ID))
	b = bytesField(b, 2, []byte("vless-reality-in"))
	b = bytesField(b, 5, []byte("tcp"))
	b = bytesField(b, 6, []byte(source))
	b = bytesField(b, 7, []byte("93.184.216.34:443")) // a destination, which princo skips
	b = bytesField(b, 8, []byte("example.com"))
	b = bytesField(b, 10, []byte(c.User))
	b = appendVarintField(b, 12, uint64(c.Created.UnixMilli()))
	if !c.Closed.IsZero() {
		b = appendVarintField(b, 13, uint64(c.Closed.UnixMilli()))
	}
	b = appendVarintField(b, 16, uint64(c.Upload))
	b = appendVarintField(b, 17, uint64(c.Download))
	return bytesField(b, 21, []byte("chain")) // repeated chainList
}

func eventMsg(typ EventType, id string, conn []byte, up, down int64) []byte {
	var b []byte
	if typ != New {
		b = appendVarintField(b, 1, uint64(typ))
	}
	b = bytesField(b, 2, []byte(id))
	if conn != nil {
		b = bytesField(b, 3, conn)
	}
	if up != 0 {
		b = appendVarintField(b, 4, uint64(up))
	}
	if down != 0 {
		b = appendVarintField(b, 5, uint64(down))
	}
	return b
}

func eventsMsg(reset bool, events ...[]byte) []byte {
	var b []byte
	for _, e := range events {
		b = bytesField(b, 1, e)
	}
	if reset {
		b = appendVarintField(b, 2, 1)
	}
	return b
}

var t0 = time.UnixMilli(1_790_000_000_000)

func TestDecodeEvents(t *testing.T) {
	c := Conn{ID: "a", User: "alice", Created: t0, Upload: 1 << 40, Download: 7}
	got, err := decodeEvents(eventsMsg(true, eventMsg(New, "a", connMsg(c, "[::ffff:203.0.113.9]:51000"), 0, 0)))
	require.NoError(t, err)
	c.Source = netip.MustParseAddr("203.0.113.9")
	require.Equal(t, Events{Reset: true, Events: []Event{{Type: New, ID: "a", Conn: &c}}}, got)

	_, err = decodeEvents(eventsMsg(false, eventMsg(New, "a", connMsg(c, "1.2.3.4:5"), 0, 0))[:20])
	require.ErrorIs(t, err, errTruncated)
}

func TestTally(t *testing.T) {
	open := Conn{ID: "1", User: "alice", Created: t0, Upload: 100, Download: 1000}
	closed := Conn{ID: "2", User: "alice", Created: t0.Add(-time.Hour), Closed: t0, Upload: 5, Download: 50}
	other := Conn{ID: "3", User: "bob", Created: t0, Upload: 1, Download: 1}
	start := Events{Reset: true, Events: []Event{
		{Type: New, ID: "1", Conn: withSource(open, "198.51.100.1")},
		{Type: New, ID: "2", Conn: withSource(closed, "198.51.100.2")},
		{Type: New, ID: "3", Conn: withSource(other, "198.51.100.1")},
	}}
	later := Events{Events: []Event{
		{Type: Update, ID: "1", UploadDelta: 10, DownloadDelta: 20},
		{Type: New, ID: "4", Conn: withSource(Conn{ID: "4", User: "alice", Created: t0.Add(time.Minute)}, "198.51.100.1")},
		{Type: Update, ID: "4", UploadDelta: 3, DownloadDelta: 4},
		{Type: Closed, ID: "3", Conn: withSource(Conn{ID: "3", User: "bob", Upload: 2, Download: 9}, "198.51.100.1"), ClosedAt: t0.Add(2 * time.Minute)},
	}}

	// What the engine remembers at the start.
	var snap Tally
	snap.Add(start, t0)
	r := snap.Report()
	require.Equal(t, 2, r.Open)
	require.Equal(t, 1, r.Closed)
	require.Equal(t, t0.Add(-time.Hour), r.Since, "the oldest connection it remembers")
	require.Equal(t, []Row{
		{User: "alice", Open: 1, Conn: 2, Upload: 105, Download: 1050, IPs: []IP{
			{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 1}, {Addr: netip.MustParseAddr("198.51.100.2"), Conns: 1},
		}},
		{User: "bob", Open: 1, Conn: 1, Upload: 1, Download: 1, IPs: []IP{{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 1}}},
	}, r.Rows)

	// What happens over a window: no connection closed before it, no
	// traffic from before it.
	w := Tally{Window: true}
	w.Add(start, t0)
	w.Add(later, t0.Add(3*time.Minute))
	r = w.Report()
	require.Equal(t, t0, r.Since)
	require.Equal(t, 2, r.Open)
	require.Equal(t, 1, r.Closed)
	require.Equal(t, []Row{
		{User: "alice", Open: 2, Conn: 2, Upload: 13, Download: 24, IPs: []IP{{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 2}}},
		{User: "bob", Conn: 1, Upload: 1, Download: 8, IPs: []IP{{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 1}}},
	}, r.Rows)
	require.Len(t, w.conns, 2, "the closed connection is folded, not kept")

	// The traffic since the last update, from the totals at the end.
	w.Settle(Events{Reset: true, Events: []Event{
		{Type: New, ID: "1", Conn: withSource(Conn{ID: "1", User: "alice", Upload: 200, Download: 2000}, "198.51.100.1")},
	}})
	require.Equal(t, int64(103), w.Report().Rows[0].Upload)
	w.Settle(Events{Reset: true, Events: []Event{
		{Type: New, ID: "4", Conn: withSource(Conn{ID: "4", User: "alice", Closed: t0.Add(4 * time.Minute), Upload: 3, Download: 4}, "198.51.100.1")},
	}})
	r = w.Report()
	require.Equal(t, 1, r.Open, "a close the window missed")
	require.Equal(t, 2, r.Closed)

	// One user's: the counts are theirs alone.
	only := Tally{User: "bob"}
	only.Add(start, t0)
	r = only.Report()
	require.Equal(t, 1, r.Open)
	require.Zero(t, r.Closed)
	require.Equal(t, t0, r.Since)
	require.Len(t, r.Rows, 1)
}

func withSource(c Conn, addr string) *Conn {
	c.Source = netip.MustParseAddr(addr)
	return &c
}

// A server speaking gRPC-Web as sing-box's API does.
func TestSubscribe(t *testing.T) {
	c := Conn{ID: "a", User: "alice", Created: t0, Upload: 3, Download: 4}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/daemon.StartedService/SubscribeConnections" || r.Header.Get("Content-Type") != "application/grpc-web+proto" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			w.Header().Set("Grpc-Status", "16")
			return
		}
		body, _ := io.ReadAll(r.Body)
		require.Equal(t, frame(0, appendVarintField(nil, 1, uint64(time.Second))), body)
		_, _ = w.Write(frame(0, eventsMsg(true, eventMsg(New, "a", connMsg(c, "192.0.2.1:1"), 0, 0))))
		_, _ = w.Write(frame(0, eventsMsg(false, eventMsg(Update, "a", nil, 1, 2))))
		_, _ = w.Write(frame(0x80, []byte("grpc-status: 0\r\n")))
	}))
	defer srv.Close()

	client := &Client{HTTP: srv.Client(), URL: srv.URL, Secret: "s3cret"}
	var got []Events
	require.NoError(t, client.Subscribe(t.Context(), time.Second, func(e Events) error {
		got = append(got, e)
		return nil
	}))
	require.Len(t, got, 2)
	require.True(t, got[0].Reset)
	require.Equal(t, int64(2), got[1].Events[0].DownloadDelta)

	client.Secret = "wrong"
	require.ErrorIs(t, client.Subscribe(t.Context(), time.Second, func(Events) error { return nil }), ErrUnauthenticated)
}

// Against sing-box itself, when it's in PATH: a user's connection through
// it shows up with the user, the source and the traffic.
func TestSubscribe_SingBox(t *testing.T) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("no sing-box in PATH")
	}
	echo := listen(t)
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	proxyPort, apiPort := freePort(t), freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": proxyPort,
			"users": []any{map[string]any{"username": "alice", "password": "pw"}},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"services": []any{map[string]any{
			"type": "api", "tag": "stats", "listen": "127.0.0.1", "listen_port": apiPort, "secret": "s3cret",
		}},
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	cmd := exec.CommandContext(t.Context(), bin, "run", "-c", path, "-D", t.TempDir())
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", proxy)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)

	// One connection through the proxy as alice, still open.
	conn, err := net.Dial("tcp", proxy)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	auth := base64.StdEncoding.EncodeToString([]byte("alice:pw"))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %[1]s\r\nProxy-Authorization: Basic %s\r\n\r\n", echo.Addr(), auth)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	payload := make([]byte, 4096)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	_, err = io.ReadFull(br, payload)
	require.NoError(t, err)

	client := &Client{HTTP: http.DefaultClient, URL: "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)), Secret: "s3cret"}
	var row Row
	require.Eventually(t, func() bool {
		var tally Tally
		err := client.Subscribe(t.Context(), time.Second, func(e Events) error {
			tally.Add(e, time.Now())
			return ErrStop
		})
		require.NoError(t, err)
		for _, r := range tally.Report().Rows {
			if r.User == "alice" {
				row = r
				return r.Upload >= int64(len(payload))
			}
		}
		return false
	}, 10*time.Second, 200*time.Millisecond)
	require.Equal(t, 1, row.Open)
	require.Equal(t, []IP{{Addr: netip.MustParseAddr("127.0.0.1"), Conns: 1}}, row.IPs)
	require.GreaterOrEqual(t, row.Download, int64(len(payload)))

	client.Secret = "wrong"
	require.ErrorIs(t, client.Subscribe(t.Context(), time.Second, func(Events) error { return ErrStop }), ErrUnauthenticated)
}

func listen(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func TestSubscribe_TrailerWithoutStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(frame(0x80, []byte("grpc-message: cut\r\n")))
	}))
	defer srv.Close()
	client := &Client{HTTP: srv.Client(), URL: srv.URL}
	err := client.Subscribe(t.Context(), time.Second, func(Events) error { return nil })
	require.ErrorContains(t, err, "ended without a status")
}
