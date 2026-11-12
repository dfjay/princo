package fleet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/config"
)

// Nodes a (WARP, sing-box) and b (direct, tagged home), then rest.
func monitored(rest string) string {
	return `
nodes:
  a:
    address: a.example.com
    reality: { server_name: s, short_id: "1", public_key: p }
    egress: warp
  b:
    address: b.example.com
    tags: [home]
    reality: { server_name: s, short_id: "2", public_key: p }
users:
  u: {}
` + rest
}

func monitorSecrets() map[string]any {
	values := conventionalSecrets()
	values["telegram"] = map[string]any{"token": "123:abc", "chat": "-100"}
	values["nodes"].(map[string]any)["a"].(map[string]any)["stats"] = "api-secret"
	return values
}

func TestBuild_Monitor(t *testing.T) {
	f, err := build(t, monitored("monitor: { from: home }"), monitorSecrets())
	require.NoError(t, err)
	require.Equal(t, &Monitor{
		Telegram: Telegram{API: "https://api.telegram.org", Token: "123:abc", Chat: "-100"},
		From:     "home",
		Interval: 2 * time.Minute,
	}, f.Monitor)

	a, _ := f.Node("a")
	b, _ := f.Node("b")
	require.Equal(t, &API{Secret: "api-secret"}, a.API, "the monitor checks WARP through the engine's API")
	require.False(t, a.Stats, "which doesn't turn princo stats on")
	require.Nil(t, b.API, "a node without WARP needs none")
	require.Equal(t, []*Node{a}, f.Reaches(b), "the tagged nodes check the others")
	require.Empty(t, f.Reaches(a))
}

func TestBuild_MonitorOptions(t *testing.T) {
	f, err := build(t, monitored(`
monitor:
  interval: 90s
  telegram: { api: https://tg.example.com/, token: plain-token, chat: !secret alerts/chat }
`), map[string]any{
		"users":  map[string]any{"u": "uuid-u"},
		"alerts": map[string]any{"chat": "42"},
		"nodes": map[string]any{
			"a": map[string]any{"reality": "k", "stats": "s", "warp": map[string]any{"private_key": "wk", "ipv4": "v4", "ipv6": "v6"}},
			"b": map[string]any{"reality": "k"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, Telegram{API: "https://tg.example.com", Token: "plain-token", Chat: "42"}, f.Monitor.Telegram)
	require.Equal(t, 90*time.Second, f.Monitor.Interval)
	a, _ := f.Node("a")
	require.Empty(t, f.Reaches(a), "no node checks the others without from")
}

func TestBuild_MonitorErrors(t *testing.T) {
	for name, tc := range map[string]struct{ rest, want string }{
		"interval too short": {"monitor: { interval: 10s }", "monitor.interval: want 1m0s or longer"},
		"interval malformed": {"monitor: { interval: often }", "monitor.interval: want a duration such as 2m"},
		"unknown tag":        {"monitor: { from: domestic }", "monitor.from: no node is tagged domestic"},
		"plain http":         {"monitor: { telegram: { api: http://tg.example.com } }", "monitor.telegram.api: want an https:// URL"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := build(t, monitored(tc.rest), monitorSecrets())
			require.ErrorContains(t, err, tc.want)
		})
	}

	_, err := build(t, monitored("monitor: {}"), conventionalSecrets())
	require.ErrorContains(t, err, "monitor.telegram.token: resolve !secret telegram/token")
	require.ErrorContains(t, err, "nodes.a.warp: resolve !secret nodes/a/stats")
}

// An xray node's WARP has no API to check it through.
func TestMonitorsWarp_Xray(t *testing.T) {
	f, err := build(t, `
nodes:
  a:
    address: a.example.com
    engine: xray
    reality: { server_name: s, short_id: "1", public_key: p }
    egress: warp
users:
  u: {}
monitor: {}
`, monitorSecrets())
	require.NoError(t, err)
	a, _ := f.Node("a")
	require.False(t, f.MonitorsWarp(a))
	require.Nil(t, a.API)
}

func TestSecrets_Monitor(t *testing.T) {
	cfg, err := config.Parse([]byte("princo: v1\n" + monitored("monitor: {}")))
	require.NoError(t, err)
	uses := Secrets(cfg)
	require.Contains(t, uses, SecretUse{"telegram/token", "monitor.telegram.token", SecretExternal})
	require.Contains(t, uses, SecretUse{"telegram/chat", "monitor.telegram.chat", SecretExternal})
	require.Contains(t, uses, SecretUse{"nodes/a/stats", "nodes.a.warp", SecretPassword}, "princo secret gen makes the API's")
}
