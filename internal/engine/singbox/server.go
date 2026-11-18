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
	if err := checkServer(n); err != nil {
		return nil, err
	}
	var sets ruleSets
	cfg := map[string]any{
		"log":          renderLog(n.Log),
		"experimental": map[string]any{"cache_file": map[string]any{"enabled": true}},
		"inbounds":     serverInbounds(f, n),
		"outbounds":    serverOutbounds(f, n),
	}
	if n.DNS != nil {
		// The node's own lookups, the REALITY handshake target's among them,
		// leave directly: through the egress, a WARP stall would refuse every
		// new connection. The xray engine routes its DNS the same way.
		cfg["dns"] = renderDNS(n.DNS, &sets, nil,
			func(fleet.DNSServer) string { return "direct" })
	}
	if n.Egress.Kind == fleet.EgressWarp {
		cfg["endpoints"] = []any{warpEndpoint(n.Warp)}
	}
	if n.API != nil {
		// Without a dashboard, which it would download.
		cfg["services"] = []any{map[string]any{
			"type":        "api",
			"tag":         "api",
			"listen":      "127.0.0.1",
			"listen_port": engine.APIPort,
			"secret":      n.API.Secret,
		}}
	}

	route := map[string]any{"final": egressTag(n)}
	// Users mustn't reach the node's own network. Domains the node resolves
	// anyway are resolved first, so this and IP rules see their addresses;
	// a chained node leaves domains to its upstream, but resolves those it
	// sends direct.
	resolved := n.Egress.Kind != fleet.EgressNode
	private := map[string]any{"ip_is_private": true, "action": "reject"}
	// The monitor's reports come first, their domains unresolved: this
	// node's DNS may lie about a channel it can't reach.
	rules := monitorRoutes(n)
	// Other nodes' reports leave directly: a stalled WARP, or a chain back
	// to their node, would keep them in.
	reporters := engine.MonitorAccounts(f, n)
	switch {
	case resolved:
		rules = append(rules, map[string]any{"action": "resolve"})
	case len(reporters) > 0:
		rules = append(rules, map[string]any{"auth_user": reporters, "action": "resolve"})
	}
	rules = append(rules, private)
	if len(reporters) > 0 {
		rules = append(rules, map[string]any{"auth_user": reporters, "action": "route", "outbound": "direct"})
	}
	for _, r := range n.Rules {
		bodies := compileMatch(r.Match, &sets)
		if !resolved && r.Action == fleet.ActionDirect {
			rules = append(rules, withAction(bodies, map[string]any{"action": "resolve"})...)
			rules = append(rules, private)
		}
		rules = append(rules, withAction(bodies, serverAction(r))...)
	}
	route["rules"] = rules
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
		// One transport: sing-box has no fallback to serve another by.
		t := r.Transports[0]
		accounts := []any{}
		for _, a := range f.Accounts(n, t) {
			account := map[string]any{"name": a.Name, "uuid": a.UUID}
			if t.Vision() {
				account["flow"] = vision
			}
			accounts = append(accounts, account)
		}
		in := map[string]any{
			"type":        "vless",
			"tag":         "vless-reality-in",
			"listen":      "::",
			"listen_port": 443,
			"users":       accounts,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": r.ServerName,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": r.TargetHost, "server_port": r.TargetPort},
					"private_key": r.PrivateKey,
					"short_id":    []any{r.ShortID},
				},
			},
		}
		if tr := transport(t); tr != nil {
			in["transport"] = tr
		}
		if n.Mux() {
			behindMux(in, engine.MuxRealityPort)
		}
		out = append(out, in)
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
			"tls":         serverTLS(f, n.Address),
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
		in := map[string]any{
			"type":  "naive",
			"tag":   "naive-in",
			"users": accounts,
			"tls":   serverTLS(f, nv.Domain),
		}
		behindMux(in, engine.MuxNaivePort)
		out = append(out, in)
	}
	if via := n.MonitorVia; len(via) > 0 {
		accounts := make([]any, 0, len(via))
		for _, up := range via {
			accounts = append(accounts, map[string]any{"username": up.Name, "password": n.MonitorUUID})
		}
		out = append(out, map[string]any{
			"type":        "socks",
			"tag":         engine.MonitorInbound,
			"listen":      "127.0.0.1",
			"listen_port": engine.MonitorPort,
			"users":       accounts,
		})
	}
	return out
}

// monitorRoutes sends each user of the monitor's proxy through their node,
// and nothing else from it anywhere.
func monitorRoutes(n *fleet.Node) []any {
	var rules []any
	for _, up := range n.MonitorVia {
		rules = append(rules, map[string]any{
			"inbound":   []any{engine.MonitorInbound},
			"auth_user": []any{up.Name},
			"action":    "route",
			"outbound":  engine.MonitorTag(up),
		})
	}
	if len(rules) > 0 {
		rules = append(rules, map[string]any{"inbound": []any{engine.MonitorInbound}, "action": "reject"})
	}
	return rules
}

// behindMux has inbound in listen on port at 127.0.0.1 and ::1 only.
func behindMux(in map[string]any, port int) {
	in["listen"] = "::"
	in["listen_port"] = port
	in["bind_interface"] = engine.LoopbackInterface
}

func serverTLS(f *fleet.Fleet, domain string) map[string]any {
	dir := path.Join(engine.CertDir, f.Certificate(domain).Name)
	return map[string]any{
		"enabled":          true,
		"server_name":      domain,
		"certificate_path": path.Join(dir, "fullchain.pem"),
		"key_path":         path.Join(dir, "key.pem"),
	}
}

func serverOutbounds(f *fleet.Fleet, n *fleet.Node) []any {
	var out []any
	if up := n.Egress.Node; up != nil {
		out = append(out, realityOutbound(up, dial(up), n.ChainUUID))
	}
	for _, up := range n.MonitorVia {
		o := realityOutbound(up, dial(up), n.MonitorUUID)
		o["tag"] = engine.MonitorTag(up)
		out = append(out, o)
	}
	direct := map[string]any{"type": "direct", "tag": "direct"}
	if n.DNS != nil {
		direct["domain_resolver"] = n.DNS.Final
	}
	return append(out, direct)
}

func egressTag(n *fleet.Node) string {
	switch n.Egress.Kind {
	case fleet.EgressWarp:
		return engine.WarpTag
	case fleet.EgressNode:
		return fleet.MemberID(n.Egress.Node, dial(n.Egress.Node).Protocol())
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
	peer := map[string]any{
		"address":     w.Host,
		"port":        w.Port,
		"public_key":  engine.WarpPeerPublicKey,
		"allowed_ips": []any{"0.0.0.0/0", "::/0"},
	}
	if w.Reserved != nil {
		peer["reserved"] = w.Reserved
	}
	return map[string]any{
		"type":        "wireguard",
		"tag":         engine.WarpTag,
		"mtu":         1280,
		"address":     []any{w.IPv4, w.IPv6},
		"private_key": w.PrivateKey,
		"peers":       []any{peer},
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
