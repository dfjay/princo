package fleet

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/secrets"
)

// Default secret paths, used when princo.yaml doesn't name one.
const (
	secretHysteria2Obfs = "shared/hysteria2_obfs"
)

func secretUserUUID(user string) string    { return "users/" + user }
func secretReality(node string) string     { return "nodes/" + node + "/reality" }
func secretWarp(node, field string) string { return "nodes/" + node + "/warp/" + field }
func secretChainUUID(node string) string   { return "nodes/" + node + "/chain" }

// engineProtocols are the protocols each engine serves.
var engineProtocols = map[string][]string{
	"sing-box": {"reality", "hysteria2", "naive"},
	"xray":     {"reality", "xhttp"},
}

var xhttpModes = []string{"auto", "packet-up", "stream-up", "stream-one"}

var hysteria2Obfs = []string{"salamander", "gecko"}

// xhttpPathRe keeps XHTTP paths safe in URLs and share links.
var xhttpPathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

// nameRe is what names of nodes, users and client groups may be: they end
// up in file and secret paths, outbound tags and links.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)

func (b *builder) checkName(where, name string) {
	if !ValidName(name) {
		b.errorf("%s: name %q: use lowercase letters, digits, - and _, starting and ending with a letter or digit", where, name)
	}
}

// Build applies defaults, resolves secrets through sec and checks every
// reference, reporting all problems at once.
func Build(cfg *config.Config, sec secrets.Getter) (*Fleet, error) {
	b := newBuilder(cfg, sec)
	b.nodes()
	b.egress()
	b.users()
	b.subscription()
	b.ruleData()
	b.client()
	if err := errors.Join(b.errs...); err != nil {
		return nil, err
	}
	return b.f, nil
}

func newBuilder(cfg *config.Config, sec secrets.Getter) *builder {
	return &builder{cfg: cfg, sec: sec, f: &Fleet{
		nodes: map[string]*Node{},
		users: map[string]*User{},
	}}
}

type builder struct {
	cfg  *config.Config
	sec  secrets.Getter
	f    *Fleet
	errs []error
	uses []SecretUse
}

func (b *builder) errorf(format string, args ...any) {
	b.errs = append(b.errs, fmt.Errorf(format, args...))
}

// secret resolves ref, or the conventional path when ref is unset.
func (b *builder) secret(where string, ref *secrets.SecretOrPlain, convention string, kind SecretKind) string {
	r := secrets.SecretOrPlain{SecretPath: convention}
	if ref != nil {
		r = *ref
	}
	if !r.IsPlain() {
		b.uses = append(b.uses, SecretUse{Path: r.SecretPath, Field: where, Kind: kind})
	}
	v, err := r.Resolve(b.sec)
	if err != nil {
		b.errorf("%s: %w", where, err)
	}
	return v
}

func (b *builder) nodes() {
	d := b.cfg.Defaults
	for _, name := range slices.Sorted(slices.Values(b.cfg.Nodes.Keys())) {
		c, _ := b.cfg.Nodes.Get(name)
		where := "nodes." + name
		b.checkName(where, name)
		n := &Node{
			Name:      name,
			SSH:       c.SSH,
			Address:   c.Address,
			Engine:    cmp.Or(c.Engine, d.Engine, "sing-box"),
			ACMEEmail: cmp.Or(c.ACMEEmail, d.ACMEEmail),
			Tags:      c.Tags,
			IPv6:      c.IPv6 == nil || *c.IPv6,
		}
		if _, ok := engineProtocols[n.Engine]; !ok {
			b.errorf("%s: engine %q is not supported (have: %s)", where, n.Engine, strings.Join(slices.Sorted(maps.Keys(engineProtocols)), ", "))
		}

		if c.Reality != nil {
			def := deref(d.Reality)
			n.Reality = &Reality{
				ServerName: cmp.Or(c.Reality.ServerName, def.ServerName),
				ShortID:    cmp.Or(c.Reality.ShortID, def.ShortID),
				PublicKey:  c.Reality.PublicKey,
				PrivateKey: b.secret(where+".reality.private_key", c.Reality.PrivateKey, secretReality(name), SecretRealityKey),
			}
			if n.Reality.ServerName == "" || n.Reality.ShortID == "" || n.Reality.PublicKey == "" {
				b.errorf("%s.reality: server_name, short_id and public_key are required", where)
			}
		}
		if c.Hysteria2 != nil {
			def, own := deref(d.Hysteria2), c.Hysteria2
			h := &Hysteria2{Obfs: cmp.Or(own.Obfs, def.Obfs)}
			switch {
			case h.Obfs == "" || h.Obfs == "none":
				h.Obfs = ""
				h.Masquerade = cmp.Or(own.Masquerade, def.Masquerade)
				if h.Masquerade == "" && n.Reality != nil {
					h.Masquerade = "https://" + n.Reality.ServerName
				}
				if h.Masquerade == "" {
					b.errorf("%s.hysteria2: masquerade is required without reality.server_name to default to", where)
				}
				if own.ObfsPassword != nil {
					b.errorf("%s.hysteria2.obfs_password: needs obfs", where)
				}
			case !slices.Contains(hysteria2Obfs, h.Obfs):
				b.errorf("%s.hysteria2.obfs: want none, %s, got %q", where, strings.Join(hysteria2Obfs, " or "), h.Obfs)
			default:
				if own.Masquerade != "" {
					b.errorf("%s.hysteria2.masquerade: has no effect with obfs, which hides the HTTP/3 server", where)
				}
				h.ObfsPassword = b.secret(where+".hysteria2.obfs_password", cmp.Or(own.ObfsPassword, def.ObfsPassword), secretHysteria2Obfs, SecretPassword)
			}
			n.Hysteria2 = h
		}
		if c.Naive != nil {
			if c.Naive.Domain == "" {
				b.errorf("%s.naive: domain is required", where)
			}
			n.Naive = &Naive{Domain: c.Naive.Domain}
		}
		if c.XHTTP != nil {
			def := deref(d.XHTTP)
			n.XHTTP = &XHTTP{
				Path: cmp.Or(c.XHTTP.Path, def.Path),
				Mode: cmp.Or(c.XHTTP.Mode, def.Mode, "auto"),
			}
			if !xhttpPathRe.MatchString(n.XHTTP.Path) {
				b.errorf("%s.xhttp.path: want a path such as /a1b2c3 (letters, digits, ., _, ~, -), got %q", where, n.XHTTP.Path)
			}
			if !slices.Contains(xhttpModes, n.XHTTP.Mode) {
				b.errorf("%s.xhttp.mode: want one of %s, got %q", where, strings.Join(xhttpModes, ", "), n.XHTTP.Mode)
			}
			if n.Reality == nil {
				b.errorf("%s.xhttp: needs reality, whose inbound serves it", where)
			}
		}
		protocols := n.Protocols()
		if len(protocols) == 0 {
			b.errorf("%s: enable at least one protocol (reality, xhttp, hysteria2, naive)", where)
		}
		if served, ok := engineProtocols[n.Engine]; ok {
			for _, p := range protocols {
				if !slices.Contains(served, p) {
					b.errorf("%s.%s: engine %s doesn't serve it", where, p, n.Engine)
				}
			}
		}
		if n.Address == "" && (n.Reality != nil || n.Hysteria2 != nil) {
			b.errorf("%s: address is required", where)
		}
		if _, err := netip.ParseAddr(n.Address); err == nil && n.Hysteria2 != nil {
			b.errorf("%s.hysteria2: needs address to be a domain, which its certificate is for", where)
		}

		if dns := cmp.Or(c.DNS, d.DNS); dns != nil {
			n.DNS = b.dns(where+".dns", dns, nil)
		}
		rules := d.Rules
		if c.Rules != nil {
			rules = c.Rules
		}
		n.Rules = b.rules(where+".rules", rules, []string{ActionDirect, ActionReject, ActionSniff}, nil, false)
		if n.Engine == "xray" {
			b.xrayLimits(where, n)
		}
		for host, target := range c.Passthrough.All() {
			n.Passthrough = append(n.Passthrough, Passthrough{Host: host, Target: target})
		}

		b.f.Nodes = append(b.f.Nodes, n)
		b.f.nodes[name] = n
	}
}

// xrayLimits reports what an xray node can't do that sing-box can.
func (b *builder) xrayLimits(where string, n *Node) {
	if n.DNS != nil {
		for _, s := range n.DNS.Servers {
			if s.Type == "tls" {
				b.errorf("%s.dns.servers.%s: xray has no DNS over TLS; use https:// or quic://", where, s.Name)
			}
		}
	}
	for i, r := range n.Rules {
		for _, m := range r.Match {
			if m.Kind == MatchNetwork && m.Value == "icmp" {
				b.errorf("%s.rules[%d]: xray doesn't route ICMP", where, i)
			}
		}
	}
}

// egress resolves each node's way out, once every node exists.
func (b *builder) egress() {
	for _, n := range b.f.Nodes {
		c, _ := b.cfg.Nodes.Get(n.Name)
		where := "nodes." + n.Name
		egress := cmp.Or(c.Egress, b.cfg.Defaults.Egress, "direct")
		switch egress {
		case "direct":
			n.Egress = Egress{Kind: EgressDirect}
		case "warp":
			n.Egress = Egress{Kind: EgressWarp}
			w := deref(c.Warp)
			n.Warp = &Warp{
				PrivateKey: b.secret(where+".warp.private_key", w.PrivateKey, secretWarp(n.Name, "private_key"), SecretExternal),
				IPv4:       b.secret(where+".warp.ipv4", w.IPv4, secretWarp(n.Name, "ipv4"), SecretExternal),
				IPv6:       b.secret(where+".warp.ipv6", w.IPv6, secretWarp(n.Name, "ipv6"), SecretExternal),
				Reserved:   w.Reserved,
			}
			if w.Reserved != nil && (len(w.Reserved) != 3 || slices.ContainsFunc(w.Reserved, func(v int) bool { return v < 0 || v > 255 })) {
				b.errorf("%s.warp.reserved: want 3 bytes, e.g. [12, 34, 56]", where)
			}
			host, port, err := net.SplitHostPort(cmp.Or(w.Endpoint, DefaultWarpEndpoint))
			p, perr := strconv.ParseUint(port, 10, 16)
			if err != nil || perr != nil || host == "" || p == 0 {
				b.errorf("%s.warp.endpoint: want host:port, e.g. engage.cloudflareclient.com:4500", where)
			}
			n.Warp.Host, n.Warp.Port = host, int(p)
		default:
			up, ok := b.f.nodes[egress]
			switch {
			case !ok:
				b.errorf("%s.egress: %q is not warp, direct or a node", where, egress)
			case up == n:
				b.errorf("%s.egress: a node can't chain to itself", where)
			case up.Reality == nil:
				b.errorf("%s.egress: chain upstream %s needs reality", where, egress)
			default:
				n.Egress = Egress{Kind: EgressNode, Node: up}
				n.ChainUUID = b.secret(where+".egress", nil, secretChainUUID(n.Name), SecretUUID)
			}
		}
	}
	// Chains must end somewhere.
	for _, n := range b.f.Nodes {
		seen := map[*Node]bool{}
		for m := n; m != nil && m.Egress.Kind == EgressNode; m = m.Egress.Node {
			if seen[m] {
				b.errorf("nodes.%s.egress: chain loops back to %s", n.Name, m.Name)
				break
			}
			seen[m] = true
		}
	}
}

func (b *builder) users() {
	for _, name := range slices.Sorted(slices.Values(b.cfg.Users.Keys())) {
		c, _ := b.cfg.Users.Get(name)
		where := "users." + name
		b.checkName(where, name)
		u := &User{Name: name, UUID: b.secret(where+".uuid", c.UUID, secretUserUUID(name), SecretUUID)}
		if c.Nodes == nil {
			u.Nodes = b.f.Nodes
		}
		for _, tag := range c.Nodes {
			n, ok := b.f.nodes[tag]
			if !ok {
				b.errorf("%s.nodes: unknown node %q", where, tag)
				continue
			}
			u.Nodes = append(u.Nodes, n)
		}
		b.f.Users = append(b.f.Users, u)
		b.f.users[name] = u
	}
}

func (b *builder) subscription() {
	c := b.cfg.Subscription
	if c == nil {
		return
	}
	n, ok := b.f.nodes[c.Node]
	if !ok {
		b.errorf("subscription.node: unknown node %q", c.Node)
		return
	}
	if c.Domain == "" {
		b.errorf("subscription.domain: required")
	}
	n.ServesSubscription = true
	b.f.Subscription = &Subscription{Node: n, Domain: c.Domain}
}

func (b *builder) client() {
	c := b.cfg.Client
	groups := c.Groups.Keys()
	for name, g := range c.Groups.All() {
		where := "client.groups." + name
		b.checkName(where, name)
		if name == "direct" {
			b.errorf("%s: \"direct\" is reserved", where)
		}
		sel, err := parseSelector(g.Nodes)
		if err != nil {
			b.errorf("%s.nodes: %w", where, err)
		}
		if g.Fallback != "" && g.Fallback != "direct" && (g.Fallback == name || !slices.Contains(groups, g.Fallback)) {
			b.errorf("%s.fallback: want direct or another group, got %q", where, g.Fallback)
		}
		def := cmp.Or(g.Default, "first")
		if g.Auto && g.Default == "" {
			def = "auto"
		}
		if g.Auto && slices.Contains(groups, name+"-auto") {
			b.errorf("%s.auto: its member is named %s-auto, like another group", where, name)
		}
		if def == "auto" && !g.Auto {
			b.errorf("%s.default: auto needs auto: true", where)
		}
		b.f.Client.Groups = append(b.f.Client.Groups, Group{
			Name:          name,
			Members:       sel,
			Default:       def,
			IncludeDirect: g.IncludeDirect,
			Auto:          g.Auto,
			Fallback:      g.Fallback,
		})
	}
	if c.DNS != nil {
		b.f.Client.DNS = b.dns("client.dns", c.DNS, groups)
	}
	// Client profiles sniff before any rule.
	b.f.Client.Rules = b.rules("client.rules", c.Rules, []string{ActionDirect, ActionReject}, groups, true)
	b.f.Client.Final = cmp.Or(c.Final, "direct")
	if b.f.Client.Final != "direct" && !slices.Contains(groups, b.f.Client.Final) {
		b.errorf("client.final: want direct or a group, got %q", b.f.Client.Final)
	}
}

// rules converts rules allowing the given actions; groups, if non-nil,
// enables `via: <group>`, and sniffed tells that traffic is sniffed before
// the first rule.
func (b *builder) rules(where string, in []config.Rule, actions, groups []string, sniffed bool) []Rule {
	out := make([]Rule, 0, len(in))
	for i, r := range in {
		w := fmt.Sprintf("%s[%d]", where, i)
		match, err := parseMatchers(r.Match)
		if err != nil {
			b.errorf("%s: %w", w, err)
		}
		if !sniffed && slices.ContainsFunc(match, func(m Matcher) bool { return m.Kind == MatchProtocol }) {
			b.errorf("%s: protocol: needs a sniff rule before it", w)
		}
		sniffed = sniffed || r.Action == ActionSniff
		rule := Rule{Match: match, Action: r.Action, Via: r.Via}
		switch {
		case r.Via != "" && r.Action != "":
			b.errorf("%s: set either action or via, not both", w)
		case r.Via != "":
			if groups == nil {
				b.errorf("%s: via is only for client rules", w)
			} else if !slices.Contains(groups, r.Via) {
				b.errorf("%s.via: unknown group %q", w, r.Via)
			}
			rule.Action = ActionVia
		case !slices.Contains(actions, r.Action):
			b.errorf("%s.action: want one of %s, got %q", w, strings.Join(actions, ", "), r.Action)
		}
		if len(match) == 0 && rule.Action != ActionSniff {
			b.errorf("%s: match is required", w)
		}
		out = append(out, rule)
	}
	return out
}

// dns converts a resolver config; groups, if non-nil, enables `via`.
func (b *builder) dns(where string, c *config.DNS, groups []string) *DNS {
	d := &DNS{
		Final:           c.Final,
		DefaultResolver: c.DefaultResolver,
		Strategy:        c.Strategy,
		Optimistic:      c.Optimistic,
	}
	names := c.Servers.Keys()
	known := func(field, name string) {
		if name != "" && !slices.Contains(names, name) {
			b.errorf("%s.%s: unknown server %q", where, field, name)
		}
	}
	for name, s := range c.Servers.All() {
		w := where + ".servers." + name
		srv, err := parseDNSAddress(s.Address)
		if err != nil {
			b.errorf("%s.address: %w", w, err)
		}
		srv.Name, srv.Via, srv.Resolver = name, s.Via, s.Resolver
		if s.Via != "" {
			if groups == nil {
				b.errorf("%s.via: only client DNS servers can go via a group", w)
			} else if !slices.Contains(groups, s.Via) {
				b.errorf("%s.via: unknown group %q", w, s.Via)
			}
		}
		known("servers."+name+".resolver", s.Resolver)
		d.Servers = append(d.Servers, srv)
	}
	if d.Final == "" {
		b.errorf("%s.final: required", where)
	}
	known("final", d.Final)
	known("default_resolver", d.DefaultResolver)
	for i, r := range c.Rules {
		w := fmt.Sprintf("%s.rules[%d]", where, i)
		match, err := parseMatchers(r.Match)
		if err != nil {
			b.errorf("%s: %w", w, err)
		}
		for _, m := range match {
			if !m.IsDomain() {
				b.errorf("%s: DNS rules match domains only, got %s", w, m)
			}
		}
		if r.Server == "" {
			b.errorf("%s.server: required", w)
		}
		known(fmt.Sprintf("rules[%d].server", i), r.Server)
		d.Rules = append(d.Rules, DNSRule{Match: match, Server: r.Server})
	}
	return d
}

func parseSelector(s string) (Selector, error) {
	switch {
	case s == "" || s == "all":
		return Selector{All: true}, nil
	case strings.HasPrefix(s, "!") && len(s) > 1:
		return Selector{Tag: s[1:], Negate: true}, nil
	case strings.HasPrefix(s, "!"):
		return Selector{}, fmt.Errorf("want <tag>, !<tag> or all, got %q", s)
	default:
		return Selector{Tag: s}, nil
	}
}

// parseDNSAddress accepts udp://, tcp://, tls://, https://, quic:// URLs
// or a bare IP (UDP).
func parseDNSAddress(s string) (DNSServer, error) {
	if !strings.Contains(s, "://") {
		s = "udp://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return DNSServer{}, fmt.Errorf("invalid DNS address %q", s)
	}
	srv := DNSServer{Type: u.Scheme, Server: u.Hostname()}
	switch u.Scheme {
	case "udp", "tcp", "tls", "quic":
	case "https":
		if u.Path != "" && u.Path != "/dns-query" {
			srv.Path = u.Path
		}
	default:
		return DNSServer{}, fmt.Errorf("DNS address %q: unsupported scheme %q", s, u.Scheme)
	}
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return DNSServer{}, fmt.Errorf("DNS address %q: bad port", s)
		}
		srv.Port = port
	}
	return srv, nil
}

func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
