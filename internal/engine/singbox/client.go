package singbox

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

func (e *Engine) ClientPlatforms() []engine.Platform { return []engine.Platform{engine.Linux} }

// RenderClient renders a user's sing-box profile for platform p.
func (e *Engine) RenderClient(f *fleet.Fleet, name string, p engine.Platform) ([]byte, error) {
	u, ok := f.User(name)
	if !ok {
		return nil, fmt.Errorf("no user named %q", name)
	}
	if p != engine.AnyPlatform && !slices.Contains(e.ClientPlatforms(), p) {
		return nil, fmt.Errorf("sing-box has no profiles for %s", p)
	}
	c := newClientView(f, u)
	var sets ruleSets

	// Where a path can't carry IPv6, refuse it IPv6, so apps fall back to
	// IPv4 instead of timing out: to the IPs routed into it, ahead of
	// everything else, and by answering no AAAA for its domains, which are
	// only known to routing once the app has connected.
	var noIPv6, noAAAA []any
	// What the rules so far match, by how far their path carries IPv6:
	// those rules match first. Ahead of sniff that is all but domains and
	// protocols; for a name, its domains.
	var earlierConns, earlierNames [ipv6Missing + 1][]any
	refuseAAAA := func(support ipv6Support, names map[string]any) {
		names["query_type"] = []any{"AAAA"}
		noAAAA = append(noAAAA, withoutIPv6(support, names,
			slices.Concat(earlierNames[:support]...), map[string]any{"action": "predefined"}))
	}
	for _, r := range u.Client.Rules {
		var out string
		switch r.Action {
		case fleet.ActionVia:
			out = c.resolve(r.Via)
		case fleet.ActionDirect:
			out = "direct"
		default:
			continue
		}
		support := c.ipv6(out)
		refused := ipOnly(r.Match)
		except := slices.Concat(earlierConns[:support]...)
		if !c.ipv4Only(out) {
			// A network without global IPv6 may still route its own.
			refused = publicOnly(refused)
			if slices.ContainsFunc(refused, func(m fleet.Matcher) bool { return m.Kind == fleet.MatchIP }) {
				except = append(except, map[string]any{"ip_is_private": true})
			}
		}
		if body := destination(refused, &sets); body != nil && support != ipv6Carried {
			body["ip_version"] = 6
			// no_drop: a burst of refusals would turn into drops.
			noIPv6 = append(noIPv6, withoutIPv6(support, body, except,
				map[string]any{"action": "reject", "no_drop": true}))
		}
		if known := beforeSniff(r.Match); len(known) > 0 {
			for _, body := range compileMatch(known, &sets) {
				earlierConns[support] = append(earlierConns[support], body)
			}
		}
		if names := domainOnly(r.Match); len(names) > 0 {
			if support != ipv6Carried {
				refuseAAAA(support, destination(names, &sets))
			}
			earlierNames[support] = append(earlierNames[support], destination(names, &sets))
		}
	}
	final := c.resolve(u.Client.Final)
	if support := c.ipv6(final); support != ipv6Carried {
		refuseAAAA(support, map[string]any{})
	}
	rules := append(noIPv6,
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	)
	for _, r := range u.Client.Rules {
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

	tun := map[string]any{
		"type":         "tun",
		"tag":          "tun-in",
		"address":      []any{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
		"auto_route":   true,
		"strict_route": true,
	}
	if p == engine.Linux {
		// nftables redirect TCP in the kernel, the LAN's on a router too.
		tun["auto_redirect"] = true
	}
	cfg := map[string]any{
		// Above warn, the apps' logs list where the user went.
		"log":          renderLog(u.Client.Log),
		"experimental": map[string]any{"cache_file": map[string]any{"enabled": true, "store_dns": true}},
		// Remote rule sets are fetched through the proxy.
		"http_clients": []any{map[string]any{"tag": "proxy-http", "detour": final}},
		"inbounds":     []any{tun},
		"outbounds":    c.outbounds(),
	}
	route := map[string]any{
		"rules":                 rules,
		"auto_detect_interface": true,
		"final":                 final,
		"default_http_client":   "proxy-http",
	}
	if d := u.Client.DNS; d != nil {
		cfg["dns"] = renderDNS(d, &sets, noAAAA, func(s fleet.DNSServer) string {
			if s.Via == "" {
				return ""
			}
			return detourOf(c.resolve(s.Via))
		})
		if d.DefaultResolver != "" {
			route["default_domain_resolver"] = d.DefaultResolver
		}
	} else if len(noAAAA) > 0 {
		// The app's own resolver answers the rest.
		cfg["dns"] = map[string]any{"rules": noAAAA}
	}
	if len(sets.tags) > 0 {
		route["rule_set"] = remoteRuleSets(f, sets.tags)
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
	for _, g := range u.Client.Groups {
		for _, n := range u.Nodes {
			if g.Members.Matches(n) {
				c.members[g.Name] = append(c.members[g.Name], n)
			}
		}
	}
	return c
}

func (c *clientView) group(name string) (fleet.Group, bool) {
	i := slices.IndexFunc(c.user.Client.Groups, func(g fleet.Group) bool { return g.Name == name })
	if i < 0 {
		return fleet.Group{}, false
	}
	return c.user.Client.Groups[i], true
}

// resolve maps a group name to the outbound traffic actually takes: the
// group's selector, or its fallback chain when the user has no members.
func (c *clientView) resolve(name string) string {
	for range len(c.user.Client.Groups) + 1 {
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

// ipv6 is how far an outbound carries IPv6. Where traffic may leave
// directly, that is the user's own network: client.ipv6, or left to the
// profile to check.
func (c *clientView) ipv6(outbound string) ipv6Support {
	if c.ipv4Only(outbound) {
		return ipv6Missing
	}
	if g, _ := c.group(outbound); outbound != "direct" && !g.IncludeDirect {
		return ipv6Carried
	}
	switch own := c.user.Client.IPv6; {
	case own == nil:
		return ipv6Uplink
	case *own:
		return ipv6Carried
	}
	return ipv6Missing
}

func (c *clientView) outbounds() []any {
	var out []any
	for _, g := range c.user.Client.Groups {
		nodes := c.members[g.Name]
		if len(nodes) == 0 {
			continue
		}
		var proxies []any
		for _, n := range nodes {
			for _, ob := range nodeOutbounds(n, c.user) {
				proxies = append(proxies, ob["tag"])
			}
		}
		var tags []any
		auto := g.Name + "-auto"
		if g.Auto {
			tags = append(tags, auto)
			out = append(out, map[string]any{"type": "urltest", "tag": auto, "outbounds": proxies})
		}
		if g.IncludeDirect {
			tags = append(tags, "direct")
		}
		tags = append(tags, proxies...)
		def := g.Default
		switch {
		case def == "auto":
			def = auto
		case def == "first", !slices.Contains(tags, any(def)):
			// The default may be a node this user can't use.
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

func remoteRuleSets(f *fleet.Fleet, tags []string) []any {
	out := make([]any, 0, len(tags))
	for _, tag := range tags {
		out = append(out, map[string]any{
			"tag":    tag,
			"type":   "remote",
			"format": "binary",
			"url":    RuleSetURL(f, tag),
		})
	}
	return out
}

// RuleSetURL is where a client profile gets a rule set: the subscription
// site, which serves the nodes' own, or else SagerNet's, which may tell
// different countries from the nodes' rule data.
func RuleSetURL(f *fleet.Fleet, tag string) string {
	if f.Subscription != nil {
		return "https://" + f.Subscription.Domain + engine.RuleSetSitePath + tag + ".srs"
	}
	repo := "sing-geosite"
	if strings.HasPrefix(tag, "geoip-") {
		repo = "sing-geoip"
	}
	return "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + tag + ".srs"
}
