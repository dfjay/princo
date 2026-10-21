package singbox

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

// RenderServer renders the sing-box config of one node.
func (e *Engine) RenderServer(f *fleet.Fleet, name string) ([]byte, error) {
	n, ok := f.Node(name)
	if !ok {
		return nil, fmt.Errorf("no node named %q", name)
	}
	var sets ruleSets
	cfg := map[string]any{
		"log":          map[string]any{"level": "warn", "timestamp": true},
		"experimental": map[string]any{"cache_file": map[string]any{"enabled": true}},
		"inbounds":     serverInbounds(f, n),
		"outbounds":    serverOutbounds(f, n),
	}
	if n.DNS != nil {
		cfg["dns"] = renderDNS(n.DNS, &sets,
			func(fleet.DNSServer) string { return "" },
			func(string) bool { return false })
	}
	if n.Egress.Kind == fleet.EgressWarp {
		cfg["endpoints"] = []any{warpEndpoint(n.Warp)}
	}

	route := map[string]any{"final": egressTag(n)}
	var rules []any
	for _, r := range n.Rules {
		rules = append(rules, withAction(compileMatch(r.Match, &sets), serverAction(r))...)
	}
	if len(rules) > 0 {
		route["rules"] = rules
	}
	if len(sets.tags) > 0 {
		route["rule_set"] = localRuleSets(sets.tags)
	}
	if n.DNS != nil && n.DNS.DefaultResolver != "" {
		route["default_domain_resolver"] = n.DNS.DefaultResolver
	}
	cfg["route"] = route

	return json.MarshalIndent(cfg, "", "  ")
}

func serverInbounds(f *fleet.Fleet, n *fleet.Node) []any {
	users := f.UsersOf(n)
	var out []any
	if r := n.Reality; r != nil {
		accounts := make([]any, 0, len(users))
		for _, u := range users {
			accounts = append(accounts, map[string]any{"uuid": u.UUID, "flow": "xtls-rprx-vision"})
		}
		// Chain hops that exit here log in like users.
		for _, m := range f.ChainsInto(n) {
			accounts = append(accounts, map[string]any{"name": "chain-" + m.Name, "uuid": m.ChainUUID, "flow": "xtls-rprx-vision"})
		}
		listen, port := "::", 443
		if n.Mux() {
			listen, port = "127.0.0.1", engine.MuxRealityPort
		}
		out = append(out, map[string]any{
			"type":        "vless",
			"tag":         "vless-reality-in",
			"listen":      listen,
			"listen_port": port,
			"users":       accounts,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": r.ServerName,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": r.ServerName, "server_port": 443},
					"private_key": r.PrivateKey,
					"short_id":    []any{r.ShortID},
				},
			},
		})
	}
	if h := n.Hysteria2; h != nil {
		accounts := make([]any, 0, len(users))
		for _, u := range users {
			accounts = append(accounts, map[string]any{"name": u.Name, "password": u.UUID})
		}
		in := map[string]any{
			"type":        "hysteria2",
			"tag":         "hysteria2-in",
			"listen":      "::",
			"listen_port": 443,
			"users":       accounts,
			"tls":         serverTLS(n.Address),
		}
		if h.Obfs != "" {
			in["obfs"] = map[string]any{"type": h.Obfs, "password": h.ObfsPassword}
		} else {
			in["masquerade"] = map[string]any{"type": "proxy", "url": h.Masquerade, "rewrite_host": true}
		}
		out = append(out, in)
	}
	if nv := n.Naive; nv != nil {
		accounts := make([]any, 0, len(users))
		for _, u := range users {
			accounts = append(accounts, map[string]any{"username": u.Name, "password": u.UUID})
		}
		out = append(out, map[string]any{
			"type":        "naive",
			"tag":         "naive-in",
			"listen":      "127.0.0.1",
			"listen_port": engine.MuxNaivePort,
			"users":       accounts,
			"tls":         serverTLS(nv.Domain),
		})
	}
	return out
}

func serverTLS(domain string) map[string]any {
	return map[string]any{
		"enabled":          true,
		"server_name":      domain,
		"certificate_path": path.Join(engine.CertDir, domain, "fullchain.pem"),
		"key_path":         path.Join(engine.CertDir, domain, "key.pem"),
	}
}

func serverOutbounds(f *fleet.Fleet, n *fleet.Node) []any {
	var out []any
	if up := n.Egress.Node; up != nil {
		out = append(out, realityOutbound(up, n.ChainUUID))
	}
	return append(out, map[string]any{"type": "direct", "tag": "direct"})
}

func egressTag(n *fleet.Node) string {
	switch n.Egress.Kind {
	case fleet.EgressWarp:
		return "warp"
	case fleet.EgressNode:
		return outboundTag(n.Egress.Node, "reality")
	default:
		return "direct"
	}
}

func serverAction(r fleet.Rule) map[string]any {
	switch r.Action {
	case fleet.ActionDirect:
		return map[string]any{"action": "route", "outbound": "direct"}
	default: // reject, sniff
		return map[string]any{"action": r.Action}
	}
}

func warpEndpoint(w *fleet.Warp) map[string]any {
	return map[string]any{
		"type":        "wireguard",
		"tag":         "warp",
		"mtu":         1280,
		"address":     []any{w.IPv4, w.IPv6},
		"private_key": w.PrivateKey,
		"peers": []any{map[string]any{
			"address":     engine.WarpPeer,
			"port":        engine.WarpPeerPort,
			"public_key":  engine.WarpPeerPublicKey,
			"allowed_ips": []any{"0.0.0.0/0", "::/0"},
		}},
	}
}

func localRuleSets(tags []string) []any {
	out := make([]any, 0, len(tags))
	for _, tag := range tags {
		out = append(out, map[string]any{
			"tag":    tag,
			"type":   "local",
			"format": "binary",
			"path":   path.Join(engine.RuleSetDir, tag+".srs"),
		})
	}
	return out
}
