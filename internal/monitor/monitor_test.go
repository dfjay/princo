package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
	// down has the engine's unit not run.
	down bool
	out  strings.Builder
	now  time.Time
}

func newHarness(t *testing.T, cfg *Config) *harness {
	h := &harness{t: t, engine: &fakeEngine{}, now: t0}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/bot123:token/sendMessage", r.URL.Path)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "-1001", r.PostForm.Get("chat_id"))
		if h.refuse {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Forbidden: bot was blocked"}`))
			return
		}
		h.sent = append(h.sent, r.PostForm.Get("text"))
	}))
	t.Cleanup(srv.Close)
	cfg.Node = "us"
	cfg.Unit = "princo.service"
	cfg.Telegram = Telegram{API: srv.URL, Token: "123:token", Chat: "-1001"}
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
	h.sent = nil
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
	require.EqualError(t, err, "telegram refused the message: Forbidden: bot was blocked")
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
	h.m.Config.Telegram.API = "https://127.0.0.1:1"
	err := h.m.Run(t.Context(), false)
	require.ErrorContains(t, err, "telegram: ")
	require.NotContains(t, err.Error(), "123:token")
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
