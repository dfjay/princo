package singbox

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/fleet"
)

// RenderClient renders the sing-box profile a user imports into their app.
func (e *Engine) RenderClient(f *fleet.Fleet, name string) ([]byte, error) {
	u, ok := f.User(name)
	if !ok {
		return nil, fmt.Errorf("no user named %q", name)
	}
	c := newClientView(f, u)
	var sets ruleSets

	// Where a group can't carry IPv6, refuse IPv6 to the IPs routed into it,
	// ahead of everything else, so apps fall back to IPv4 instead of timing
	// out on whichever rule would have matched.
	var noIPv6 []any
	for _, r := range f.Client.Rules {
		if r.Action == fleet.ActionVia && c.ipv4Only(c.resolve(r.Via)) {
			if ips := ipOnly(r.Match); len(ips) > 0 {
				noIPv6 = append(noIPv6, withAction(compileMatch(ips, &sets), map[string]any{
					"ip_version": 6,
					"action":     "reject",
				})...)
			}
		}
	}
	rules := append(noIPv6,
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	)
	for _, r := range f.Client.Rules {
		bodies := compileMatch(r.Match, &sets)
		switch r.Action {
		case fleet.ActionVia:
			rules = append(rules, withAction(bodies, map[string]any{"action": "route", "outbound": c.resolve(r.Via)})...)
		case fleet.ActionDirect:
			rules = append(rules, withAction(bodies, map[string]any{"action": "route", "outbound": "direct"})...)
		case fleet.ActionReject:
			rules = append(rules, withAction(bodies, map[string]any{"action": "reject"})...)
		}
	}

	final := c.resolve(f.Client.Final)
	cfg := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"experimental": map[string]any{
			"clash_api":  map[string]any{"external_controller": "127.0.0.1:9090", "default_mode": "Rule"},
			"cache_file": map[string]any{"enabled": true, "store_dns": true},
		},
		// Remote rule sets are fetched through the proxy.
		"http_clients": []any{map[string]any{"tag": "proxy-http", "detour": final}},
		"inbounds": []any{map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []any{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route":   true,
			"strict_route": true,
		}},
		"outbounds": c.outbounds(),
	}
	route := map[string]any{
		"rules":                 rules,
		"auto_detect_interface": true,
		"final":                 final,
		"default_http_client":   "proxy-http",
	}
	if d := f.Client.DNS; d != nil {
		cfg["dns"] = renderDNS(d, &sets,
			func(s fleet.DNSServer) string {
				if s.Via == "" {
					return ""
				}
				return detourOf(c.resolve(s.Via))
			},
			func(server string) bool {
				i := slices.IndexFunc(d.Servers, func(s fleet.DNSServer) bool { return s.Name == server })
				return i >= 0 && d.Servers[i].Via != "" && c.ipv4Only(c.resolve(d.Servers[i].Via))
			})
		if d.DefaultResolver != "" {
			route["default_domain_resolver"] = d.DefaultResolver
		}
	}
	if len(sets.tags) > 0 {
		route["rule_set"] = remoteRuleSets(sets.tags)
	}
	cfg["route"] = route

	return json.MarshalIndent(cfg, "", "  ")
}

// detourOf turns an outbound into a DNS detour; "direct" means none.
func detourOf(outbound string) string {
	if outbound == "direct" {
		return ""
	}
	return outbound
}

// clientView is the fleet as one user sees it: their nodes, and the groups
// that have at least one of them.
type clientView struct {
	f       *fleet.Fleet
	user    *fleet.User
	members map[string][]*fleet.Node // group name → member nodes
}

func newClientView(f *fleet.Fleet, u *fleet.User) *clientView {
	c := &clientView{f: f, user: u, members: map[string][]*fleet.Node{}}
	for _, g := range f.Client.Groups {
		for _, n := range u.Nodes {
			if g.Members.Matches(n) {
				c.members[g.Name] = append(c.members[g.Name], n)
			}
		}
	}
	return c
}

func (c *clientView) group(name string) (fleet.Group, bool) {
	i := slices.IndexFunc(c.f.Client.Groups, func(g fleet.Group) bool { return g.Name == name })
	if i < 0 {
		return fleet.Group{}, false
	}
	return c.f.Client.Groups[i], true
}

// resolve maps a group name to the outbound traffic actually takes: the
// group's selector, or its fallback chain when the user has no members.
func (c *clientView) resolve(name string) string {
	for range len(c.f.Client.Groups) + 1 {
		if name == "direct" || len(c.members[name]) > 0 {
			return name
		}
		g, ok := c.group(name)
		if !ok || g.Fallback == "" {
			return "direct"
		}
		name = g.Fallback
	}
	return "direct"
}

// ipv4Only reports whether an outbound includes a node without IPv6.
func (c *clientView) ipv4Only(outbound string) bool {
	return slices.ContainsFunc(c.members[outbound], func(n *fleet.Node) bool { return !n.IPv6 })
}

func (c *clientView) outbounds() []any {
	var out []any
	for _, g := range c.f.Client.Groups {
		nodes := c.members[g.Name]
		if len(nodes) == 0 {
			continue
		}
		var tags []any
		if g.IncludeDirect {
			tags = append(tags, "direct")
		}
		for _, n := range nodes {
			for _, ob := range nodeOutbounds(n, c.user) {
				tags = append(tags, ob["tag"])
			}
		}
		def := g.Default
		if def == "first" {
			def = outboundTag(nodes[0], firstProtocol(nodes[0]))
		}
		out = append(out, map[string]any{"type": "selector", "tag": g.Name, "outbounds": tags, "default": def})
	}
	for _, n := range c.user.Nodes {
		for _, ob := range nodeOutbounds(n, c.user) {
			out = append(out, ob)
		}
	}
	return append(out, map[string]any{"type": "direct", "tag": "direct"})
}

func outboundTag(n *fleet.Node, protocol string) string { return n.Name + "-" + protocol }

func firstProtocol(n *fleet.Node) string {
	switch {
	case n.Reality != nil:
		return "reality"
	case n.Hysteria2 != nil:
		return "hysteria2"
	default:
		return "naive"
	}
}

// nodeOutbounds is how user reaches n: one outbound per protocol.
func nodeOutbounds(n *fleet.Node, u *fleet.User) []map[string]any {
	var out []map[string]any
	if n.Reality != nil {
		out = append(out, realityOutbound(n, u.UUID))
	}
	if h := n.Hysteria2; h != nil {
		o := map[string]any{
			"type":        "hysteria2",
			"tag":         outboundTag(n, "hysteria2"),
			"server":      n.Address,
			"server_port": 443,
			"password":    u.UUID,
			"tls":         map[string]any{"enabled": true, "server_name": n.Address},
		}
		if h.Obfs != "" {
			o["obfs"] = map[string]any{"type": h.Obfs, "password": h.ObfsPassword}
		}
		out = append(out, o)
	}
	if nv := n.Naive; nv != nil {
		out = append(out, map[string]any{
			"type":        "naive",
			"tag":         outboundTag(n, "naive"),
			"server":      nv.Domain,
			"server_port": 443,
			"username":    u.Name,
			"password":    u.UUID,
			"tls":         map[string]any{"enabled": true, "server_name": nv.Domain},
		})
	}
	return out
}

// realityOutbound connects to n's VLESS-Reality inbound as uuid; clients and
// chain hops alike.
func realityOutbound(n *fleet.Node, uuid string) map[string]any {
	r := n.Reality
	return map[string]any{
		"type":        "vless",
		"tag":         outboundTag(n, "reality"),
		"server":      n.Address,
		"server_port": 443,
		"uuid":        uuid,
		"flow":        "xtls-rprx-vision",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": r.ServerName,
			"reality":     map[string]any{"enabled": true, "public_key": r.PublicKey, "short_id": r.ShortID},
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
		},
	}
}

func remoteRuleSets(tags []string) []any {
	out := make([]any, 0, len(tags))
	for _, tag := range tags {
		out = append(out, map[string]any{
			"tag":    tag,
			"type":   "remote",
			"format": "binary",
			"url":    RuleSetURL(tag),
		})
	}
	return out
}

// RuleSetURL is where SagerNet publishes a geosite-*/geoip-* rule set.
func RuleSetURL(tag string) string {
	repo := "sing-geosite"
	if strings.HasPrefix(tag, "geoip-") {
		repo = "sing-geoip"
	}
	return "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + tag + ".srs"
}
