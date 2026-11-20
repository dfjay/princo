package singbox

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

func (e *Engine) ClientPlatforms() []engine.Platform { return []engine.Platform{engine.Linux} }

// RenderClient renders a user's sing-box profile for platform p, its rule
// sets from the subscription site at domain.
func (e *Engine) RenderClient(f *fleet.Fleet, name string, p engine.Platform, domain string) ([]byte, error) {
	u, ok := f.User(name)
	if !ok {
		return nil, fmt.Errorf("no user named %q", name)
	}
	if p != engine.AnyPlatform && !slices.Contains(e.ClientPlatforms(), p) {
		return nil, fmt.Errorf("sing-box has no profiles for %s", p)
	}
	for _, n := range u.Nodes {
		if err := checkRenders(n, n.Dials(engineName)); err != nil {
			return nil, err
		}
	}
	c := newClientView(f, u)
	var sets ruleSets

	// The app takes its profile from the site the way the fleet reaches
	// domain (see fleet.SiteFetch). A domain reached directly comes ahead
	// of the user's rules: through the proxy, a dead node would keep the
	// app from the profile that replaces it.
	clientRules := u.Client.Rules
	siteDirect := f.Subscription.FetchDirect(domain)
	origin := f.Subscription.RuleSetOrigin(domain)
	if siteDirect {
		site := fleet.Rule{
			Match:  []fleet.Matcher{{Kind: fleet.MatchDomain, Value: strings.ToLower(domain)}},
			Action: fleet.ActionDirect,
		}
		clientRules = append([]fleet.Rule{site}, clientRules...)
	}

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
	for _, r := range clientRules {
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
	for _, r := range clientRules {
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
	// The rule sets are sing-box's own to fetch, past the tunnel and the
	// rules: from their origin directly, or through the final outbound.
	rulesHTTP := map[string]any{"tag": "rules-http"}
	// sing-box refuses a detour to an empty direct outbound.
	if detour := detourOf(final); !origin.Direct && detour != "" {
		rulesHTTP["detour"] = detour
	}
	cfg := map[string]any{
		// Above warn, the apps' logs list where the user went.
		"log":          renderLog(u.Client.Log),
		"experimental": map[string]any{"cache_file": map[string]any{"enabled": true, "store_dns": true}},
		"http_clients": []any{rulesHTTP},
		"inbounds":     []any{tun},
		"outbounds":    c.outbounds(),
	}
	route := map[string]any{
		"rules":                 rules,
		"auto_detect_interface": true,
		"final":                 final,
		"default_http_client":   "rules-http",
	}
	if d := u.Client.DNS; d != nil {
		serverDetour := func(s fleet.DNSServer) string {
			if s.Via == "" {
				return ""
			}
			return detourOf(c.resolve(s.Via))
		}
		first := noAAAA
		// Its name too, or the lookup would wait on the proxy all the same:
		// ahead of the user's rules, as one by geosite may send it there.
		if server := siteServer(d, strings.ToLower(domain), serverDetour); siteDirect && server != "" {
			first = append(first, map[string]any{
				"domain": []any{strings.ToLower(domain)},
				"action": "route",
				"server": server,
			})
		}
		// sing-box asks no DNS rule for its own lookups, only the default
		// resolver, which may wait on the proxy.
		if server := siteServer(d, originHost(origin), serverDetour); origin.Direct && server != "" {
			rulesHTTP["domain_resolver"] = server
		}
		cfg["dns"] = renderDNS(d, &sets, first, serverDetour)
		if d.DefaultResolver != "" {
			route["default_domain_resolver"] = d.DefaultResolver
		}
	} else if len(noAAAA) > 0 {
		// The app's own resolver answers the rest.
		cfg["dns"] = map[string]any{"rules": noAAAA}
	}
	if len(sets.tags) > 0 {
		route["rule_set"] = remoteRuleSets(origin, sets.tags)
	}
	cfg["route"] = route

	return json.MarshalIndent(cfg, "", "  ")
}

// siteServer is the DNS server that looks up the name of a site reached
// directly, one that needs no proxy: the server d's own rules give the
// name, else final, the default resolver or the first such; empty when
// every one goes through the proxy. A rule set's names aren't known here,
// so a rule matching by geosite gives it none.
func siteServer(d *fleet.DNS, domain string, detour func(fleet.DNSServer) string) string {
	// Without the proxy, and so its own name's lookup, down the resolvers.
	direct := func(name string) bool {
		for range d.Servers {
			i := slices.IndexFunc(d.Servers, func(s fleet.DNSServer) bool { return s.Name == name })
			if i < 0 || detour(d.Servers[i]) != "" {
				return false
			}
			if _, err := netip.ParseAddr(d.Servers[i].Server); err == nil {
				return true
			}
			if name = cmp.Or(d.Servers[i].Resolver, d.DefaultResolver); name == "" {
				return true
			}
		}
		return false // resolvers in a circle
	}
	candidates := []string{d.Final, d.DefaultResolver}
	if i := slices.IndexFunc(d.Rules, func(r fleet.DNSRule) bool { return namesDomain(r.Match, domain) }); i >= 0 {
		candidates = slices.Insert(candidates, 0, d.Rules[i].Server)
	}
	for _, s := range d.Servers {
		candidates = append(candidates, s.Name)
	}
	if i := slices.IndexFunc(candidates, direct); i >= 0 {
		return candidates[i]
	}
	return ""
}

// namesDomain reports whether match names domain itself, as sing-box
// reads it, rather than through a rule set.
func namesDomain(match []fleet.Matcher, domain string) bool {
	return slices.ContainsFunc(match, func(m fleet.Matcher) bool {
		v := strings.ToLower(m.Value)
		switch m.Kind {
		case fleet.MatchDomain:
			return v == domain
		case fleet.MatchDomainSuffix:
			// A leading dot leaves the name itself out.
			return strings.HasSuffix(domain, "."+strings.TrimPrefix(v, ".")) || v == domain
		case fleet.MatchDomainKeyword:
			return strings.Contains(domain, v)
		}
		return false
	})
}

// detourOf turns an outbound into a detour of a DNS server or HTTP client;
// "direct" means none, as sing-box refuses a detour to an empty direct
// outbound.
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
	members map[string][]member // group name → its members
}

// member is a way out through a node: straight to it, or through relay,
// which then sees only the connection to exit.
type member struct {
	exit  *fleet.Node
	relay *fleet.Node // nil when straight
}

// tags are the member's outbounds as the profile shows them, one per
// protocol, and ids how princo.yaml refers to each. Through a relay that
// is Reality alone, by the transport dial picks.
func (c *clientView) tags(p member) (tags []any, ids []string) {
	if p.relay != nil {
		id := fleet.MemberID(p.exit, dial(p.exit).Protocol())
		return []any{c.relayedTag(p)}, []string{fleet.Relayed(id, p.relay)}
	}
	for _, protocol := range p.exit.ClientProtocols() {
		tags = append(tags, c.tag(p.exit, protocol))
		ids = append(ids, fleet.MemberID(p.exit, protocol))
	}
	return tags, ids
}

// tag is what the profile shows for n's protocol.
func (c *clientView) tag(n *fleet.Node, protocol string) string {
	return c.user.Client.Name(c.user, n, protocol)
}

func (c *clientView) relayedTag(p member) string {
	return fleet.Relayed(c.tag(p.exit, dial(p.exit).Protocol()), p.relay)
}

func newClientView(f *fleet.Fleet, u *fleet.User) *clientView {
	c := &clientView{f: f, user: u, members: map[string][]member{}}
	for _, g := range u.Client.Groups {
		var straight []member
		for _, n := range u.Nodes {
			// A node may serve nothing the profile speaks.
			if g.Members.Matches(n) && len(n.ClientProtocols()) > 0 {
				straight = append(straight, member{exit: n})
			}
		}
		// The straight ones first, so they stay the first member.
		c.members[g.Name] = straight
		if g.Relay == nil {
			continue
		}
		for _, relay := range u.Nodes {
			if !g.Relay.Matches(relay) || !dials(relay) {
				continue
			}
			for _, p := range straight {
				if p.exit != relay && dials(p.exit) {
					c.members[g.Name] = append(c.members[g.Name], member{exit: p.exit, relay: relay})
				}
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
	// A relay only carries the connection to the exit, whatever is in it.
	return slices.ContainsFunc(c.members[outbound], func(p member) bool { return !p.exit.IPv6 })
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
		members := c.members[g.Name]
		if len(members) == 0 {
			continue
		}
		var proxies []any
		byID := map[string]any{}
		for _, p := range members {
			tags, ids := c.tags(p)
			proxies = append(proxies, tags...)
			for i, id := range ids {
				byID[id] = tags[i]
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
		// The default may be a member this user hasn't got.
		def := proxies[0]
		switch member, ok := byID[g.Default]; {
		case g.Default == "auto":
			def = auto
		case g.Default == "direct" && g.IncludeDirect:
			def = "direct"
		case ok:
			def = member
		}
		out = append(out, map[string]any{"type": "selector", "tag": g.Name, "outbounds": tags, "default": def})
	}
	for _, n := range c.user.Nodes {
		for _, ob := range nodeOutbounds(n, c.user, func(protocol string) string { return c.tag(n, protocol) }) {
			out = append(out, ob)
		}
	}
	// Each relayed member once, however many groups offer it.
	relayed := map[string]bool{}
	for _, g := range c.user.Client.Groups {
		for _, p := range c.members[g.Name] {
			if p.relay == nil {
				continue
			}
			tag := c.relayedTag(p)
			if relayed[tag] {
				continue
			}
			relayed[tag] = true
			ob := realityOutbound(p.exit, dial(p.exit), c.user.UUID)
			ob["tag"] = tag
			ob["detour"] = c.tag(p.relay, dial(p.relay).Protocol())
			out = append(out, ob)
		}
	}
	return append(out, map[string]any{"type": "direct", "tag": "direct"})
}

// dial is the transport sing-box connects to n's Reality by where it
// takes one; dials tells whether there is one.
func dial(n *fleet.Node) fleet.Transport {
	t, _ := n.Dial(engineName)
	return t
}

func dials(n *fleet.Node) bool { return len(n.Dials(engineName)) > 0 }

// nodeOutbounds is how user reaches n: one outbound per protocol, in the
// order of n.ClientProtocols, each tagged as tag names its protocol.
func nodeOutbounds(n *fleet.Node, u *fleet.User, tag func(protocol string) string) []map[string]any {
	var out []map[string]any
	for _, t := range n.Dials(engineName) {
		o := realityOutbound(n, t, u.UUID)
		o["tag"] = tag(t.Protocol())
		out = append(out, o)
	}
	if h := n.Hysteria2; h != nil {
		o := map[string]any{
			"type":        "hysteria2",
			"tag":         tag("hysteria2"),
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
			"tag":         tag("naive"),
			"server":      nv.Domain,
			"server_port": 443,
			"username":    u.Name,
			"password":    u.UUID,
			"tls":         map[string]any{"enabled": true, "server_name": nv.Domain},
		})
	}
	return out
}

const vision = "xtls-rprx-vision"

// realityOutbound connects to n's VLESS-Reality inbound by t as uuid,
// tagged with its fleet.MemberID; clients and chain hops alike.
func realityOutbound(n *fleet.Node, t fleet.Transport, uuid string) map[string]any {
	r := n.Reality
	out := map[string]any{
		"type":        "vless",
		"tag":         fleet.MemberID(n, t.Protocol()),
		"server":      n.Address,
		"server_port": 443,
		"uuid":        uuid,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": r.ServerName,
			"reality":     map[string]any{"enabled": true, "public_key": r.PublicKey, "short_id": r.ShortID},
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
		},
	}
	if t.Vision() {
		out["flow"] = vision
	}
	if tr := transport(t); tr != nil {
		out["transport"] = tr
	}
	return out
}

// transports are sing-box's V2Ray transports by kind, the same on both
// sides; nil for tcp, which needs none.
var transports = map[string]func(fleet.Transport) map[string]any{
	fleet.TransportTCP: func(fleet.Transport) map[string]any { return nil },
	fleet.TransportGRPC: func(t fleet.Transport) map[string]any {
		return map[string]any{"type": "grpc", "service_name": t.ServiceName}
	},
}

// transport renders t, which checkRenders saw is one of transports.
func transport(t fleet.Transport) map[string]any { return transports[t.Kind](t) }

// checkServer refuses what the server renderer would make something else
// of: transports of n's that sing-box doesn't serve together, or a node n
// connects to by none. fleet.Build lets none through, so this is for a
// fleet built otherwise.
func checkServer(n *fleet.Node) error {
	if r := n.Reality; r != nil {
		if err := checkRenders(n, r.Transports); err != nil {
			return err
		}
		if !fleet.ServesTogether(engineName, r.Transports) {
			return fmt.Errorf("node %s: sing-box serves one reality transport, got %d", n.Name, len(r.Transports))
		}
	}
	for _, up := range n.Upstreams() {
		ts := up.Dials(engineName)
		if len(ts) == 0 {
			return fmt.Errorf("node %s: no reality transport sing-box connects by", up.Name)
		}
		if err := checkRenders(up, ts); err != nil {
			return err
		}
	}
	return nil
}

// checkRenders refuses a transport fleet lists for sing-box before
// transports has it.
func checkRenders(n *fleet.Node, ts []fleet.Transport) error {
	for _, t := range ts {
		if transports[t.Kind] == nil {
			return fmt.Errorf("node %s: sing-box renders no reality transport %q", n.Name, t.Kind)
		}
	}
	return nil
}

func remoteRuleSets(origin fleet.RuleSetOrigin, tags []string) []any {
	out := make([]any, 0, len(tags))
	for _, tag := range tags {
		out = append(out, map[string]any{
			"tag":    tag,
			"type":   "remote",
			"format": "binary",
			"url":    RuleSetURL(origin, tag),
		})
	}
	return out
}

// RuleSetURL is where a client profile gets a rule set: at its origin,
// which holds the nodes' own, or without one SagerNet's, which may tell
// different countries from the nodes' rule data.
func RuleSetURL(origin fleet.RuleSetOrigin, tag string) string {
	if origin.URL != "" {
		return origin.URL + tag + ".srs"
	}
	repo := "sing-geosite"
	if strings.HasPrefix(tag, "geoip-") {
		repo = "sing-geoip"
	}
	return "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + tag + ".srs"
}

// originHost is the host the rule sets of origin are fetched from, in
// lowercase; empty for the upstream.
func originHost(origin fleet.RuleSetOrigin) string {
	u, err := url.Parse(origin.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
