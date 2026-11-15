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
	values["monitor"] = map[string]any{
		"ops":  map[string]any{"token": "123:abc", "chat": "-100"},
		"hook": map[string]any{"url": "https://hooks.example.com/t0ken"},
	}
	values["nodes"].(map[string]any)["a"].(map[string]any)["api"] = "api-secret"
	return values
}

const ops = "notify: { ops: { type: telegram } }"

func TestBuild_Monitor(t *testing.T) {
	f, err := build(t, monitored(`
monitor:
  notify:
    ops: { type: telegram }
    hook: { type: webhook }
  reach:
    - { from: home }
`), monitorSecrets())
	require.NoError(t, err)
	require.Equal(t, &Monitor{
		Notify: []Channel{
			{Name: "hook", Webhook: &Webhook{URL: "https://hooks.example.com/t0ken"}},
			{Name: "ops", Telegram: &Telegram{API: "https://api.telegram.org", Token: "123:abc", Chat: "-100"}},
		},
		Interval:           2 * time.Minute,
		Confirm:            2,
		CertificateWarning: 14 * 24 * time.Hour,
		Reach:              []Reach{{From: Selector{Tag: "home"}, To: Selector{All: true}}},
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
  confirm: 3
  certificate_days: 7
  notify:
    tg: { type: telegram, api: https://tg.example.com/, token: plain-token, chat: !secret alerts/chat }
  reach:
    - { from: all, to: "!home" }
`), map[string]any{
		"users":  map[string]any{"u": "uuid-u"},
		"alerts": map[string]any{"chat": "42"},
		"nodes": map[string]any{
			"a": map[string]any{"reality": "k", "api": "s", "warp": map[string]any{"private_key": "wk", "ipv4": "v4", "ipv6": "v6"}},
			"b": map[string]any{"reality": "k"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, []Channel{{Name: "tg", Telegram: &Telegram{API: "https://tg.example.com", Token: "plain-token", Chat: "42"}}}, f.Monitor.Notify)
	require.Equal(t, 90*time.Second, f.Monitor.Interval)
	require.Equal(t, 3, f.Monitor.Confirm)
	require.Equal(t, 7*24*time.Hour, f.Monitor.CertificateWarning)
	a, _ := f.Node("a")
	b, _ := f.Node("b")
	require.Empty(t, f.Reaches(a), "a node doesn't check itself")
	require.Equal(t, []*Node{a}, f.Reaches(b))
}

func TestBuild_MonitorErrors(t *testing.T) {
	for name, tc := range map[string]struct{ rest, want string }{
		"interval too short": {"monitor: { " + ops + ", interval: 10s }", "monitor.interval: want 1m0s or longer"},
		"interval malformed": {"monitor: { " + ops + ", interval: often }", "monitor.interval: want a duration such as 2m"},
		"confirm":            {"monitor: { " + ops + ", confirm: 0 }", "monitor.confirm: want 1 or more runs, got 0"},
		"certificate days":   {"monitor: { " + ops + ", certificate_days: 0 }", "monitor.certificate_days: want 1 or more, got 0"},
		"unknown tag":        {"monitor: { " + ops + ", reach: [{ from: domestic }] }", "monitor.reach[0].from: no node matches domestic"},
		"unknown target":     {"monitor: { " + ops + ", reach: [{ from: home, to: abroad }] }", "monitor.reach[0].to: no node matches abroad"},
		"no source":          {"monitor: { " + ops + ", reach: [{ to: home }] }", "monitor.reach[0].from: want the nodes that check"},
		"plain http":         {"monitor: { notify: { ops: { type: telegram, api: http://tg.example.com } } }", "monitor.notify.ops.api: want an https:// URL"},
		"query mark":         {"monitor: { notify: { ops: { type: telegram, api: 'https://tg.example.com/?' } } }", "monitor.notify.ops.api: want an https:// URL"},
		"fragment mark":      {"monitor: { notify: { ops: { type: telegram, api: 'https://tg.example.com/#' } } }", "monitor.notify.ops.api: want an https:// URL"},
		"no channel":         {"monitor: {}", "monitor.notify: want a channel to tell"},
		"unknown type":       {"monitor: { notify: { ops: { type: pager } } }", `monitor.notify.ops.type: want telegram or webhook, got "pager"`},
		"another's field":    {"monitor: { notify: { hook: { type: webhook, chat: x } } }", "monitor.notify.hook.chat: a webhook channel has none"},
		"empty value":        {`monitor: { notify: { ops: { type: telegram, chat: "" } } }`, "monitor.notify.ops.chat: is empty"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := build(t, monitored(tc.rest), monitorSecrets())
			require.ErrorContains(t, err, tc.want)
		})
	}

	_, err := build(t, monitored("monitor: { "+ops+" }"), conventionalSecrets())
	require.ErrorContains(t, err, "monitor.notify.ops.token: resolve !secret monitor/ops/token")
	require.ErrorContains(t, err, "nodes.a.warp: resolve !secret nodes/a/api")
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
monitor: { `+ops+` }
`, monitorSecrets())
	require.NoError(t, err)
	a, _ := f.Node("a")
	require.False(t, f.MonitorsWarp(a))
	require.Nil(t, a.API)
}

func TestSecrets_Monitor(t *testing.T) {
	cfg, err := config.Parse([]byte("princo: v1\n" + monitored("monitor: { notify: { ops: { type: telegram }, hook: { type: webhook } } }")))
	require.NoError(t, err)
	uses := Secrets(cfg)
	require.Contains(t, uses, SecretUse{"monitor/ops/token", "monitor.notify.ops.token", SecretExternal})
	require.Contains(t, uses, SecretUse{"monitor/ops/chat", "monitor.notify.ops.chat", SecretExternal})
	require.Contains(t, uses, SecretUse{"monitor/hook/url", "monitor.notify.hook.url", SecretExternal})
	require.Contains(t, uses, SecretUse{"nodes/a/api", "nodes.a.warp", SecretPassword}, "princo secret gen makes the API's")
}
