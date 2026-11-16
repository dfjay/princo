package monitor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/certtest"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

// fakeEngine is an engine whose WARP fails with warpErr.
type fakeEngine struct {
	warpErr error
}

func (e *fakeEngine) TestOutbound(context.Context, string) (time.Duration, error) {
	return 80 * time.Millisecond, e.warpErr
}

// harness runs a monitor whose clock moves a minute a run.
type harness struct {
	t      *testing.T
	m      *Monitor
	engine *fakeEngine
	// sent are the messages Telegram got; refuse has it answer an error.
	sent   []string
	refuse bool
	// hooks are the bodies the webhook got, once newHarness's caller sets
	// one; refuseHook has it answer an error.
	hooks      []string
	refuseHook bool
	url        string
	// down has the engine's unit not run.
	down bool
	out  strings.Builder
	now  time.Time
}

func newHarness(t *testing.T, cfg *Config) *harness {
	h := &harness{t: t, engine: &fakeEngine{}, now: t0}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hook/s3cret" {
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			if h.refuseHook {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			body, _ := io.ReadAll(r.Body)
			h.hooks = append(h.hooks, string(body))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		require.Equal(t, "/bot123:token/sendMessage", r.URL.Path)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "-1001", r.PostForm.Get("chat_id"))
		if h.refuse {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Forbidden: bot was blocked"}`))
			return
		}
		h.sent = append(h.sent, r.PostForm.Get("text"))
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	t.Cleanup(srv.Close)
	cfg.Node = "us"
	cfg.Unit = "princo.service"
	h.url = srv.URL
	cfg.Confirm, cfg.CertificateDays = 2, 14
	cfg.Notify = []Channel{{Name: "ops", Telegram: &Telegram{API: srv.URL, Token: "123:token", Chat: "-1001"}}}
	h.m = &Monitor{
		Config:    cfg,
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Out:       &h.out,
		Now:       func() time.Time { return h.now },
		HTTP:      srv.Client(),
		Dial:      (&net.Dialer{}).DialContext,
		Active: func(_ context.Context, unit string) error {
			require.Equal(t, "princo.service", unit)
			if h.down {
				return errors.New("inactive")
			}
			return nil
		},
		Engine: h.engine,
	}
	return h
}

// run runs the monitor once and returns what it sent to Telegram.
func (h *harness) run() []string {
	h.t.Helper()
	h.sent, h.hooks = nil, nil
	require.NoError(h.t, h.m.Run(h.t.Context(), false))
	h.now = h.now.Add(time.Minute)
	return h.sent
}

func warpConfig() *Config {
	return &Config{Warp: &Warp{URL: "http://127.0.0.1:8446", Secret: "s", Outbound: "warp"}}
}

func TestRun_Warp(t *testing.T) {
	h := newHarness(t, warpConfig())
	require.Empty(t, h.run(), "a healthy node says nothing")

	h.engine.warpErr = errors.New("the test request got no answer")
	require.Empty(t, h.run(), "one failure may be a lost packet")
	require.Equal(t, []string{"princo node us\n🔴 WARP is down: the test request got no answer. Traffic through the node stalls."}, h.run())
	require.Empty(t, h.run(), "it tells of a change once")

	h.engine.warpErr = nil
	require.Empty(t, h.run(), "one answer isn't back yet")
	require.Equal(t, []string{"princo node us\n🟢 WARP works again, after 3m"}, h.run())
}

func TestRun_EngineDown(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.run()
	h.down = true
	h.engine.warpErr = errors.New("unreachable")
	h.run()
	// WARP's state stays: the engine's own check tells.
	require.Equal(t, []string{"princo node us\n🔴 The engine is down: princo.service isn't running"}, h.run())

	h.down, h.engine.warpErr = false, nil
	h.run()
	require.Equal(t, []string{"princo node us\n🟢 The engine runs again, after 2m"}, h.run())
}

// More changes than a message holds go out in several, none lost.
func TestRun_SplitsLongReports(t *testing.T) {
	cfg := &Config{}
	for i := range 150 {
		cfg.Reach = append(cfg.Reach, Target{Node: fmt.Sprintf("node%03d", i), Address: "192.0.2.1", Port: 443})
	}
	h := newHarness(t, cfg)
	h.m.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	h.run()
	sent := h.run()
	require.Greater(t, len(sent), 1)
	lines := 0
	for _, text := range sent {
		require.LessOrEqual(t, utf8.RuneCountInString(text), maxMessage)
		require.True(t, strings.HasPrefix(text, "princo node us\n🔴 Can't reach node node"), text)
		lines += strings.Count(text, "\n")
	}
	require.Equal(t, 150, lines)
	require.Empty(t, h.run(), "each was told")
}

// A skipped check breaks the row: the failures around it don't add up.
func TestRun_SkippedCheckResetsStreak(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.run()
	h.engine.warpErr = errors.New("no answer")
	h.run()
	h.down = true
	h.run()
	h.down = false
	require.Empty(t, h.run(), "one failure after the engine's own, which isn't down for one run either")
	require.Len(t, h.run(), 1)
}

func TestRun_TelegramRetries(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.engine.warpErr = errors.New("no answer")
	h.run()
	h.refuse = true
	err := h.m.Run(t.Context(), false)
	require.EqualError(t, err, "ops: it refused the message: Forbidden: bot was blocked")
	h.refuse = false
	require.Len(t, h.run(), 1, "the next run tells what the failed one couldn't")
	require.Empty(t, h.run())
}

// What Telegram never heard went down isn't announced as back.
func TestRun_UnreportedBlip(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.engine.warpErr = errors.New("no answer")
	h.run()
	h.refuse = true
	require.Error(t, h.m.Run(t.Context(), false))
	h.engine.warpErr = nil
	require.Error(t, h.m.Run(t.Context(), false))
	h.refuse = false
	require.Empty(t, h.run())
	require.Empty(t, h.run())
}

func TestRun_TelegramErrorsHideTheToken(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.engine.warpErr = errors.New("no answer")
	h.run()
	h.m.Config.Notify[0].Telegram.API = "https://127.0.0.1:1"
	err := h.m.Run(t.Context(), false)
	require.ErrorContains(t, err, "ops: ")
	require.NotContains(t, err.Error(), "123:token")
}

// Each channel hears of a change once, whatever the other does.
func TestRun_Webhook(t *testing.T) {
	h := newHarness(t, warpConfig())
	hook := Channel{Name: "hook", Webhook: &Webhook{URL: h.url + "/hook/s3cret"}}
	h.m.Config.Notify = append(h.m.Config.Notify, hook)
	h.engine.warpErr = errors.New("no answer")
	h.run()
	h.refuseHook = true
	err := h.m.Run(t.Context(), false)
	require.EqualError(t, err, "hook: it answered 502 Bad Gateway")
	require.Len(t, h.sent, 1, "Telegram heard")

	h.refuseHook = false
	require.Empty(t, h.run(), "and doesn't again")
	require.Len(t, h.hooks, 1, "the webhook hears what it missed")
	require.JSONEq(t, `{
		"node": "us",
		"text": "princo node us\n🔴 WARP is down: no answer. Traffic through the node stalls.",
		"changes": [{
			"check": "warp", "down": true, "detail": "no answer",
			"text": "🔴 WARP is down: no answer. Traffic through the node stalls."
		}]
	}`, h.hooks[0])
	h.run()
	require.Empty(t, h.hooks)

	// A channel pointed elsewhere hears the state anew: it is another.
	elsewhere := hook
	elsewhere.Webhook = &Webhook{URL: h.url + "/hook/other"}
	require.NotEqual(t, hook.id(), elsewhere.id())
	require.Regexp(t, `^hook:[0-9a-f]{8}$`, hook.id())
}

// A redirect leads to a page that isn't the webhook's answer.
func TestRun_WebhookRedirect(t *testing.T) {
	h := newHarness(t, warpConfig())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hook" {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)
	h.m.Config.Notify = []Channel{{Name: "hook", Webhook: &Webhook{URL: srv.URL + "/hook"}}}
	h.engine.warpErr = errors.New("no answer")
	h.run()
	require.EqualError(t, h.m.Run(t.Context(), false), "hook: it answered 302 Found")
}

func TestRun_WebhookErrorsHideTheURL(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.m.Config.Notify = []Channel{{Name: "hook", Webhook: &Webhook{URL: "https://127.0.0.1:1/hook/s3cret"}}}
	h.engine.warpErr = errors.New("no answer")
	h.run()
	err := h.m.Run(t.Context(), false)
	require.ErrorContains(t, err, "hook: ")
	require.NotContains(t, err.Error(), "s3cret")
}

// A relay's page isn't the Bot API taking the message.
func TestRun_TelegramWantsItsAnswer(t *testing.T) {
	h := newHarness(t, warpConfig())
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>welcome</html>"))
	}))
	t.Cleanup(relay.Close)
	h.m.Config.Notify[0].Telegram.API = relay.URL
	h.engine.warpErr = errors.New("no answer")
	h.run()
	require.EqualError(t, h.m.Run(t.Context(), false), "ops: it answered 200 OK, and not as the Bot API does")
}

// A run cut short keeps no count of what it couldn't finish.
func TestRun_Canceled(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.run()
	h.engine.warpErr = errors.New("no answer")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for range 3 {
		require.ErrorIs(t, h.m.Run(ctx, false), context.Canceled)
	}
	require.Empty(t, h.run(), "the first failure it counts")
}

func TestRun_OneAtATime(t *testing.T) {
	h := newHarness(t, warpConfig())
	unlock, err := lock(h.m.StatePath)
	require.NoError(t, err)
	require.EqualError(t, h.m.Run(t.Context(), false), "another run is under way; --dry-run checks beside it")
	require.NoError(t, h.m.Run(t.Context(), true))
	unlock()
	h.run()
}

func TestRun_DryRun(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.engine.warpErr = errors.New("no answer")
	for range 3 {
		require.NoError(t, h.m.Run(t.Context(), true))
	}
	require.Empty(t, h.sent)
	require.NoFileExists(t, h.m.StatePath)
	require.Contains(t, h.out.String(), "ok   engine\nFAIL warp: no answer\n")
}

func TestRun_Certificates(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, notAfter time.Time) Certificate {
		file := filepath.Join(dir, name+".pem")
		require.NoError(t, os.WriteFile(file, certtest.Expiring(t, notAfter, name), 0o600))
		return Certificate{Name: name, File: file}
	}
	h := newHarness(t, &Config{Certificates: []Certificate{
		write("fresh.example.com", t0.Add(60*24*time.Hour)),
		write("due.example.com", t0.Add(9*24*time.Hour+time.Hour)),
		{Name: "gone.example.com", File: filepath.Join(dir, "gone.pem")},
	}})
	h.run()
	sent := h.run()
	require.Len(t, sent, 1)
	require.Contains(t, sent[0], "🔴 Certificate due.example.com: expires in 9 days, on 2026-11-21")
	require.Contains(t, sent[0], "🔴 Certificate gone.example.com: can't read it")
	require.NotContains(t, sent[0], "fresh.example.com")

	// Renewed.
	write("due.example.com", t0.Add(90*24*time.Hour))
	h.run()
	require.Equal(t, []string{"princo node us\n🟢 Certificate due.example.com is fine again: expires in 89 days, on 2027-02-10"}, h.run())
}

// A server that missed a renewal goes on presenting the old certificate.
func TestRun_ServedCertificate(t *testing.T) {
	const name = "subs.example.com"
	pair := func(notAfter time.Time) (string, *tls.Certificate) {
		chain, key := certtest.ExpiringPair(t, notAfter, "shop.example.com", name)
		c, err := tls.X509KeyPair([]byte(chain), []byte(key))
		require.NoError(t, err)
		return chain, &c
	}
	_, old := pair(t0.Add(20 * 24 * time.Hour))
	renewed, fresh := pair(t0.Add(80 * 24 * time.Hour))
	var presents atomic.Pointer[tls.Certificate]
	presents.Store(old)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return presents.Load(), nil
		},
	})
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).HandshakeContext(t.Context())
				_ = conn.Close()
			}()
		}
	}()
	file := filepath.Join(t.TempDir(), "fullchain.pem")
	require.NoError(t, os.WriteFile(file, []byte(renewed), 0o600))
	addr := ln.Addr().String()
	h := newHarness(t, &Config{Certificates: []Certificate{{Name: "wild", File: file, Served: []Served{
		{Unit: "princo.service", Address: addr, ServerName: "shop.example.com"},
		{Unit: "nginx.service", Address: addr, ServerName: name},
	}}}})

	const stale = " presents one that expires on 2026-12-02, not wild on disk"
	h.run()
	sent := h.run()
	require.Len(t, sent, 1)
	require.Contains(t, sent[0], "🔴 Certificate served as shop.example.com: princo.service"+stale)
	require.Contains(t, sent[0], "🔴 Certificate served as subs.example.com: nginx.service"+stale)
	require.NotContains(t, sent[0], "Certificate wild", "the file is fine")

	// Down with the engine, its server says nothing of the certificate:
	// not that it loaded the new one either.
	h.down = true
	presents.Store(fresh)
	h.run()
	require.Equal(t, []string{"princo node us\n🔴 The engine is down: princo.service isn't running\n🟢 Certificate served as subs.example.com is the one on disk again, after 2m"}, h.run())
	require.NotContains(t, h.out.String(), "served/shop.example.com: princo.service presents wild\n")

	h.down = false
	h.run()
	require.Equal(t, []string{"princo node us\n🟢 The engine runs again, after 2m\n🟢 Certificate served as shop.example.com is the one on disk again, after 4m"}, h.run())

	require.NoError(t, ln.Close())
	h.run()
	sent = h.run()
	require.Len(t, sent, 1)
	require.Contains(t, sent[0], "🔴 Certificate served as subs.example.com: can't ask nginx.service at "+addr+": ")

	// Without the certificate on disk there is nothing to compare with.
	require.NoError(t, os.Remove(file))
	h.out.Reset()
	h.run()
	require.Contains(t, h.out.String(), "FAIL certificate/wild: can't read it")
	require.NotContains(t, h.out.String(), "served/")
}

func TestRun_Reach(t *testing.T) {
	// A TLS server, as a node's Reality hands the handshake to a site.
	site := httptest.NewTLSServer(http.NotFoundHandler())
	defer site.Close()
	_, port, err := net.SplitHostPort(site.Listener.Addr().String())
	require.NoError(t, err)
	p, err := strconv.Atoi(port)
	require.NoError(t, err)
	// A port that accepts and then says nothing of TLS.
	mute, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = mute.Close() }()
	go func() {
		for {
			c, err := mute.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := closed.Addr().(*net.TCPAddr).Port
	require.NoError(t, closed.Close())

	h := newHarness(t, &Config{Reach: []Target{
		{Node: "de", Address: "127.0.0.1", Port: p, ServerName: "www.example.com"},
		{Node: "fi", Address: "127.0.0.1", Port: mute.Addr().(*net.TCPAddr).Port, ServerName: "www.example.com"},
		{Node: "us", Address: "127.0.0.1", Port: closedPort, ServerName: "www.example.com"},
		{Node: "plain", Address: "127.0.0.1", Port: mute.Addr().(*net.TCPAddr).Port},
	}})
	h.run()
	sent := h.run()
	require.Len(t, sent, 1)
	lines := strings.Split(sent[0], "\n")
	require.Len(t, lines, 3, sent[0])
	require.Contains(t, lines[1], "🔴 Can't reach node fi: TLS handshake with 127.0.0.1:")
	require.Contains(t, lines[2], "🔴 Can't reach node us: connecting to 127.0.0.1:")
	require.Contains(t, lines[2], "connection refused")

	// fi answers again.
	h.m.Config.Reach[1].Port = p
	h.run()
	require.Equal(t, []string{"princo node us\n🟢 Node fi is reachable again, after 2m"}, h.run())
}

// A check that is gone, with its node, leaves the state without a word.
func TestRun_ForgetsRemovedChecks(t *testing.T) {
	h := newHarness(t, &Config{Reach: []Target{{Node: "us", Address: "127.0.0.1", Port: 1}}})
	h.run()
	require.Len(t, h.run(), 1)
	h.m.Config.Reach = nil
	require.Empty(t, h.run())
	data, err := os.ReadFile(h.m.StatePath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "reach/us")
}

func TestSpan(t *testing.T) {
	for d, want := range map[time.Duration]string{
		20 * time.Second:              "less than a minute",
		12 * time.Minute:              "12m",
		2*time.Hour + 13*time.Minute:  "2h13m",
		76*time.Hour + 20*time.Minute: "3d4h",
	} {
		require.Equal(t, want, span(d))
	}
}

// via has the harness's channel told through nodes, and returns the nodes
// tried, in order. A node in carries stops answering after that many
// requests.
func (h *harness) via(nodes []string, carries map[string]int) *[]string {
	var tried []string
	h.m.Config.Notify[0].Via = nodes
	direct := h.m.HTTP.Transport
	h.m.Via = func(node string) *http.Client {
		return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			tried = append(tried, node)
			if left, ok := carries[node]; ok && left == 0 {
				return nil, errors.New("connection reset")
			}
			carries[node]--
			return direct.RoundTrip(r)
		})}
	}
	return &tried
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRun_Via(t *testing.T) {
	h := newHarness(t, warpConfig())
	tried := h.via([]string{"de", "fi", "us"}, map[string]int{"de": 0})
	h.engine.warpErr = errors.New("no answer")
	h.run()
	require.Len(t, h.run(), 1, "fi tells what de couldn't")
	require.Equal(t, []string{"de", "fi"}, *tried)
}

// The nodes this one can't reach come last: the report of it mustn't wait
// for them.
func TestRun_ViaSkipsUnreachable(t *testing.T) {
	h := newHarness(t, &Config{Reach: []Target{{Node: "de", Address: "192.0.2.1", Port: 443}}})
	tried := h.via([]string{"de", "fi"}, map[string]int{"de": 0})
	h.m.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	h.run()
	require.Equal(t, []string{"princo node us\n🔴 Can't reach node de: connecting to 192.0.2.1:443: connection refused"}, h.run())
	require.Equal(t, []string{"fi"}, *tried)
}

// A run tries so many nodes, and never on its own: the node can't reach
// the channel.
func TestRun_ViaGivesUp(t *testing.T) {
	h := newHarness(t, warpConfig())
	tried := h.via([]string{"a", "b", "c", "d"}, map[string]int{"a": 0, "b": 0, "c": 0, "d": 0})
	h.engine.warpErr = errors.New("no answer")
	h.run()
	err := h.m.Run(t.Context(), false)
	require.EqualError(t, err, "ops: through a: connection reset\nthrough b: connection reset\nthrough c: connection reset")
	require.Equal(t, []string{"a", "b", "c"}, *tried)
	require.Empty(t, h.sent)
}

// The next run starts with the nodes the last one didn't try, and comes
// back to a node once a report has left through it.
func TestRun_ViaRotates(t *testing.T) {
	h := newHarness(t, warpConfig())
	tried := h.via([]string{"a", "b", "c", "d"}, map[string]int{"a": 0, "b": 0, "c": 0})
	h.engine.warpErr = errors.New("no answer")
	h.run()
	require.Error(t, h.m.Run(t.Context(), false))
	h.now = h.now.Add(time.Minute)
	*tried = nil
	require.Len(t, h.run(), 1)
	require.Equal(t, []string{"d"}, *tried)

	h.engine.warpErr = nil
	h.run()
	*tried = nil
	require.Len(t, h.run(), 1)
	require.Equal(t, []string{"d"}, *tried, "the others failed since")
}

// A node that answers and then goes quiet didn't carry the report.
func TestRun_ViaCutShort(t *testing.T) {
	h := newHarness(t, warpConfig())
	h.m.Config.Notify[0].Via = []string{"de", "fi"}
	direct := h.m.HTTP.Transport
	h.m.Via = func(node string) *http.Client {
		return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if node == "de" {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(iotest.ErrReader(errors.New("connection reset")))}, nil
			}
			return direct.RoundTrip(r)
		})}
	}
	h.engine.warpErr = errors.New("no answer")
	h.run()
	require.Len(t, h.run(), 1)
}

// A channel that answers and refuses would refuse through any node.
func TestRun_ViaRefused(t *testing.T) {
	h := newHarness(t, warpConfig())
	tried := h.via([]string{"de", "fi"}, map[string]int{})
	h.engine.warpErr = errors.New("no answer")
	h.run()
	h.refuse = true
	err := h.m.Run(t.Context(), false)
	require.EqualError(t, err, "ops: through de: it refused the message: Forbidden: bot was blocked")
	require.Equal(t, []string{"de"}, *tried)
}

// A node that fails midway leaves the rest to the next: nothing is told
// twice.
func TestRun_ViaGoesOn(t *testing.T) {
	cfg := &Config{}
	for i := range 150 {
		cfg.Reach = append(cfg.Reach, Target{Node: fmt.Sprintf("node%03d", i), Address: "192.0.2.1", Port: 443})
	}
	h := newHarness(t, cfg)
	h.via([]string{"de", "fi"}, map[string]int{"de": 1})
	h.m.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	h.run()
	lines := 0
	for _, text := range h.run() {
		lines += strings.Count(text, "\n")
	}
	require.Equal(t, 150, lines)
	require.Empty(t, h.run())
}

// Which nodes carry the reports is no part of where they go.
func TestChannelID_Via(t *testing.T) {
	ch := Channel{Name: "ops", Telegram: &Telegram{API: "https://api.telegram.org", Token: "t", Chat: "c"}}
	id := ch.id()
	ch.Via = []string{"de"}
	require.Equal(t, id, ch.id())
}

func TestProxyURL(t *testing.T) {
	p := &Proxy{Address: "127.0.0.1:8447", Password: "p w"}
	require.Equal(t, "socks5h://de:p%20w@127.0.0.1:8447", p.URL("de").String())
}
