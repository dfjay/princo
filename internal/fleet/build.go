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
	"time"
	"unicode"

	"github.com/dfjay/princo/internal/config"
	"github.com/dfjay/princo/internal/secrets"
)

// Default secret paths, used when princo.yaml doesn't name one.
const secretHysteria2Obfs = "shared/hysteria2_obfs"

func secretChannel(name, field string) string { return "monitor/" + name + "/" + field }
func secretUserUUID(user string) string       { return "users/" + user }
func secretReality(node string) string        { return "nodes/" + node + "/reality" }
func secretWarp(node, field string) string    { return "nodes/" + node + "/warp/" + field }
func secretChainUUID(node string) string      { return "nodes/" + node + "/chain" }
func secretAPI(node string) string            { return "nodes/" + node + "/api" }
func secretMonitorUUID(node string) string    { return "nodes/" + node + "/monitor" }

// engineProtocols are the protocols each engine serves; engineTransports
// are the ways into reality.
var engineProtocols = map[string][]string{
	SingBox: {"reality", "hysteria2", "naive"},
	Xray:    {"reality"},
}

var xhttpModes = []string{"auto", "packet-up", "stream-up", "stream-one"}

var hysteria2Obfs = []string{"salamander", "gecko"}

// xhttpPathRe keeps XHTTP paths safe in URLs and share links, and
// grpcServiceRe gRPC service names, which are a path segment.
var (
	xhttpPathRe   = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)
	grpcServiceRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

// nameRe is what names of nodes, users and client groups may be: they end
// up in file and secret paths, outbound tags and links.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)

// hostnameRe is a DNS name: dot-separated labels of letters, digits and
// inner hyphens.
var hostnameRe = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

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
	b.certificates()
	b.monitor()
	b.realityNames()
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
	defaultLog := b.logLevel("defaults.log", d.Log)
	for _, name := range slices.Sorted(slices.Values(b.cfg.Nodes.Keys())) {
		c, _ := b.cfg.Nodes.Get(name)
		where := "nodes." + name
		b.checkName(where, name)
		n := &Node{
			Name:      name,
			SSH:       c.SSH,
			Address:   c.Address,
			Engine:    cmp.Or(c.Engine, d.Engine, SingBox),
			ACMEEmail: cmp.Or(c.ACMEEmail, d.ACMEEmail),
			Tags:      c.Tags,
			IPv6:      c.IPv6 == nil || *c.IPv6,
			Log:       defaultLog,
		}
		if c.Log != "" {
			n.Log = b.logLevel(where+".log", c.Log)
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
				Transports: b.transports(where+".reality.transports", n.Engine, c.Reality.Transports, def.Transports),
			}
			if n.Reality.ServerName == "" || n.Reality.ShortID == "" || n.Reality.PublicKey == "" {
				b.errorf("%s.reality: server_name, short_id and public_key are required", where)
			}
			n.Reality.TargetHost, n.Reality.TargetPort = n.Reality.ServerName, 443
			if target := cmp.Or(c.Reality.Target, def.Target); target != "" {
				var ok bool
				if n.Reality.TargetHost, n.Reality.TargetPort, ok = hostPort(target); !ok {
					b.errorf("%s.reality.target: want host:port, e.g. 127.0.0.1:8443, got %q", where, target)
				}
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
		protocols := n.Protocols()
		if len(protocols) == 0 {
			b.errorf("%s: enable at least one protocol (reality, hysteria2, naive)", where)
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
		if on := cmp.Or(c.Stats, d.Stats); on != nil && *on {
			if n.Engine != "sing-box" {
				b.errorf("%s.stats: engine %s doesn't report connections; only sing-box does", where, n.Engine)
			}
			n.Stats = true
			b.api(n, where+".stats")
		}

		b.f.Nodes = append(b.f.Nodes, n)
		b.f.nodes[name] = n
	}
}

// transports resolves a reality block's transports, own over the defaults
// def, and checks that engine serves them: tcp alone without the block.
func (b *builder) transports(where, engine string, own, def *config.Transports) []Transport {
	if own == nil {
		return []Transport{{Kind: TransportTCP}}
	}
	d := deref(def)
	var out []Transport
	if own.TCP != nil {
		out = append(out, Transport{Kind: TransportTCP})
	}
	if own.GRPC != nil {
		t := Transport{Kind: TransportGRPC, ServiceName: cmp.Or(own.GRPC.ServiceName, deref(d.GRPC).ServiceName)}
		if !grpcServiceRe.MatchString(t.ServiceName) {
			b.errorf("%s.grpc.service_name: want a name such as a1b2c3 (letters, digits, ., _, ~, -), got %q", where, t.ServiceName)
		}
		out = append(out, t)
	}
	if own.XHTTP != nil {
		def := deref(d.XHTTP)
		t := Transport{
			Kind: TransportXHTTP,
			Path: cmp.Or(own.XHTTP.Path, def.Path),
			Mode: cmp.Or(own.XHTTP.Mode, def.Mode, "auto"),
		}
		if !xhttpPathRe.MatchString(t.Path) {
			b.errorf("%s.xhttp.path: want a path such as /a1b2c3 (letters, digits, ., _, ~, -), got %q", where, t.Path)
		}
		if !slices.Contains(xhttpModes, t.Mode) {
			b.errorf("%s.xhttp.mode: want one of %s, got %q", where, strings.Join(xhttpModes, ", "), t.Mode)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		b.errorf("%s: enable at least one transport (%s)", where, strings.Join(TransportKinds, ", "))
		// So what connects to the node doesn't report it again.
		return []Transport{{Kind: TransportTCP}}
	}

	speaks, ok := engineTransports[engine]
	if !ok {
		return out // reported with the node
	}
	served := true
	for _, t := range out {
		if !slices.Contains(speaks, t.Kind) {
			b.errorf("%s.%s: engine %s doesn't serve it", where, t.Kind, engine)
			served = false
		}
	}
	if served && !ServesTogether(engine, out) {
		beside := engineFallbacks[engine]
		limit := "one transport at a time"
		if len(beside) > 0 {
			limit += ", or tcp with " + strings.Join(beside, " or ")
		}
		b.errorf("%s: engine %s serves %s", where, engine, limit)
	}
	return out
}

// hostPort splits host:port, where host is an IP or a hostname.
func hostPort(s string) (string, int, bool) {
	host, port, err := net.SplitHostPort(s)
	p, perr := strconv.ParseUint(port, 10, 16)
	_, aerr := netip.ParseAddr(host)
	// 253 is the longest name DNS can carry.
	return host, int(p), err == nil && perr == nil && p != 0 && (aerr == nil || len(host) <= 253 && hostnameRe.MatchString(host))
}

// loopsBack reports whether n's Reality target is where its own Reality
// listens: 443 on the node, or behind the multiplexer, which sends
// whatever it doesn't route to Reality. Names are compared, not resolved:
// another name of the node gets through, as docs/config.md warns.
func loopsBack(n *Node) bool {
	host, port := n.Reality.TargetHost, n.Reality.TargetPort
	ip, err := netip.ParseAddr(host)
	local := err == nil && (ip.IsLoopback() || ip.IsUnspecified()) || strings.EqualFold(host, "localhost")
	own := local || strings.EqualFold(host, n.Address)
	return own && (port == 443 || local && n.Mux() && port == MuxRealityPort)
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
	// chains are the nodes' upstreams as written, valid or not.
	chains := map[*Node]*Node{}
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
			var ok bool
			if n.Warp.Host, n.Warp.Port, ok = hostPort(cmp.Or(w.Endpoint, DefaultWarpEndpoint)); !ok {
				b.errorf("%s.warp.endpoint: want host:port, e.g. engage.cloudflareclient.com:4500", where)
			}
		default:
			up, ok := b.f.nodes[egress]
			if ok {
				chains[n] = up
			}
			switch {
			case !ok:
				b.errorf("%s.egress: %q is not warp, direct or a node", where, egress)
			case up == n:
				b.errorf("%s.egress: a node can't chain to itself", where)
			case up.Reality == nil:
				b.errorf("%s.egress: chain upstream %s needs reality", where, egress)
			case len(up.Dials(n.Engine)) == 0 && engineTransports[n.Engine] != nil:
				b.errorf("%s.egress: engine %s can't connect to chain upstream %s, which serves reality over %s alone", where, n.Engine, egress, kinds(up.Reality.Transports))
			default:
				n.Egress = Egress{Kind: EgressNode, Node: up}
				n.ChainUUID = b.secret(where+".egress", nil, secretChainUUID(n.Name), SecretUUID)
			}
		}
	}
	// Chains must end somewhere: as princo.yaml has them, so that a hop
	// refused for another reason doesn't hide a loop until it is fixed.
	for _, n := range b.f.Nodes {
		seen := map[*Node]bool{}
		for m := n; chains[m] != nil && chains[m] != m; m = chains[m] {
			if seen[m] {
				b.errorf("nodes.%s.egress: chain loops back to %s", n.Name, m.Name)
				break
			}
			seen[m] = true
		}
	}
}

// monitor resolves monitor: and gives the nodes whose WARP it checks their
// engine's API, once egress is known.
func (b *builder) monitor() {
	c := b.cfg.Monitor
	if c == nil {
		return
	}
	m := &Monitor{
		Interval:        DefaultMonitorInterval,
		Confirm:         DefaultMonitorConfirm,
		CertificateDays: DefaultCertificateDays,
	}
	for _, name := range slices.Sorted(slices.Values(c.Notify.Keys())) {
		ch, _ := c.Notify.Get(name)
		m.Notify = append(m.Notify, b.channel("monitor.notify."+name, name, ch))
	}
	if len(m.Notify) == 0 {
		b.errorf("monitor.notify: want a channel to tell, e.g. ops: { type: telegram }")
	}
	if c.Interval != "" {
		d, err := time.ParseDuration(c.Interval)
		switch {
		case err != nil:
			b.errorf("monitor.interval: want a duration such as 2m, got %q", c.Interval)
		case d < MinMonitorInterval || d%time.Second != 0:
			b.errorf("monitor.interval: want %s or longer, in whole seconds, got %s", MinMonitorInterval, c.Interval)
		default:
			m.Interval = d
		}
	}
	if c.Confirm != nil {
		if m.Confirm = *c.Confirm; m.Confirm < 1 {
			b.errorf("monitor.confirm: want 1 or more runs, got %d", m.Confirm)
		}
	}
	if c.CertificateDays != nil {
		if m.CertificateDays = *c.CertificateDays; m.CertificateDays < 1 {
			b.errorf("monitor.certificate_days: want 1 or more, got %d", m.CertificateDays)
		}
	}
	for i, r := range c.Reach {
		where := fmt.Sprintf("monitor.reach[%d]", i)
		rule := Reach{To: b.selector(where+".to", r.To)}
		// Empty is all for to; here it would have every node check.
		if r.From == "" {
			b.errorf("%s.from: want the nodes that check: <tag>, !<tag> or all", where)
			continue
		}
		rule.From = b.selector(where+".from", r.From)
		m.Reach = append(m.Reach, rule)
	}
	b.f.Monitor = m
	for _, n := range b.f.Nodes {
		if b.f.MonitorsWarp(n) {
			b.api(n, "nodes."+n.Name+".warp")
		}
		for _, ch := range m.Notify {
			// No node with reality at all is the channel's own error.
			if ch.Via != nil && !ch.Via.Matches(n) && len(b.f.Via(n, ch)) == 0 &&
				slices.ContainsFunc(b.f.Nodes, func(up *Node) bool { return ch.Via.Matches(up) && up.Reality != nil }) {
				b.errorf("monitor.notify.%s.via: engine %s of node %s speaks no reality transport of the nodes it selects", ch.Name, n.Engine, n.Name)
			}
		}
		for _, up := range b.f.Nodes {
			if slices.ContainsFunc(m.Notify, func(ch Channel) bool { return slices.Contains(b.f.Via(n, ch), up) }) {
				n.MonitorVia = append(n.MonitorVia, up)
			}
		}
		if len(n.MonitorVia) > 0 {
			n.MonitorUUID = b.secret("monitor.notify", nil, secretMonitorUUID(n.Name), SecretUUID)
			if n.MonitorUUID == "" {
				// The engine would leave its proxy open to the host's every user.
				b.errorf("monitor.notify: the secret %s is empty", secretMonitorUUID(n.Name))
			}
		}
	}
}

// channel resolves the channel name of monitor.notify.
func (b *builder) channel(where, name string, c config.Channel) Channel {
	b.checkName(where, name)
	out := Channel{Name: name}
	unused := func(field string, set bool) {
		if set {
			b.errorf("%s.%s: a %s channel has none", where, field, c.Type)
		}
	}
	switch c.Type {
	case "telegram":
		unused("url", c.URL != nil)
		out.Telegram = &Telegram{
			API:   strings.TrimSuffix(cmp.Or(c.API, DefaultTelegramAPI), "/"),
			Token: b.filled(where+".token", c.Token, secretChannel(name, "token")),
			Chat:  b.filled(where+".chat", c.Chat, secretChannel(name, "chat")),
		}
		if u, err := url.Parse(out.Telegram.API); err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(out.Telegram.API, "#") {
			b.errorf("%s.api: want an https:// URL, got %q", where, c.API)
		}
	case "webhook":
		unused("token", c.Token != nil)
		unused("chat", c.Chat != nil)
		unused("api", c.API != "")
		out.Webhook = &Webhook{URL: b.filled(where+".url", c.URL, secretChannel(name, "url"))}
		// Unless it is a placeholder: princo plan has no secrets.
		if v := out.Webhook.URL; v != "" && len(secrets.Placeholders([]byte(v))) == 0 {
			if u, err := url.Parse(v); err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
				// Not quoted: it is a secret.
				b.errorf("%s.url: want an http:// or https:// URL", where)
			}
		}
	default:
		b.errorf("%s.type: want telegram or webhook, got %q", where, c.Type)
	}
	if c.Via != "" {
		sel, err := parseSelector(c.Via)
		switch {
		case err != nil:
			b.errorf("%s.via: %v", where, err)
		case slices.ContainsFunc(b.f.Nodes, func(n *Node) bool { return !sel.Matches(n) }) &&
			!slices.ContainsFunc(b.f.Nodes, func(n *Node) bool { return sel.Matches(n) && n.Reality != nil }):
			// The nodes it leaves out have no one to report through.
			b.errorf("%s.via: no node with reality matches %s", where, c.Via)
		}
		out.Via = &sel
	}
	return out
}

// filled resolves a secret from outside princo that mustn't be empty.
func (b *builder) filled(where string, ref *secrets.SecretOrPlain, convention string) string {
	errs := len(b.errs)
	v := b.secret(where, ref, convention, SecretExternal)
	if v == "" && len(b.errs) == errs {
		b.errorf("%s: is empty", where)
	}
	return v
}

// selector parses s, which must select a node.
func (b *builder) selector(where, s string) Selector {
	sel, err := parseSelector(s)
	switch {
	case err != nil:
		b.errorf("%s: %v", where, err)
	case !slices.ContainsFunc(b.f.Nodes, sel.Matches):
		b.errorf("%s: no node matches %s", where, s)
	}
	return sel
}

// api turns on the API of n's engine, which where in princo.yaml needs.
func (b *builder) api(n *Node, where string) {
	if n.API != nil {
		return
	}
	n.API = &API{Secret: b.secret(where, nil, secretAPI(n.Name), SecretPassword)}
	if n.API.Secret == "" {
		// sing-box would leave its API open to the host's every user.
		b.errorf("%s: the secret %s is empty", where, secretAPI(n.Name))
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
	// The multiplexer routes each name once, whatever its case.
	taken := map[string]string{}
	n, ok := b.f.nodes[c.Node]
	if !ok {
		b.errorf("subscription.node: unknown node %q", c.Node)
	} else {
		for _, pt := range n.Passthrough {
			taken[strings.ToLower(pt.Host)] = fmt.Sprintf("nodes.%s.passthrough sends it to %s", n.Name, pt.Target)
		}
		if n.Naive != nil {
			taken[strings.ToLower(n.Naive.Domain)] = fmt.Sprintf("nodes.%s.naive.domain takes it to Naive; give one of them another name", n.Name)
		}
	}
	if len(c.Domains) == 0 {
		b.errorf("subscription.domains: required")
		return
	}
	s := &Subscription{Node: n, RuleSets: map[string]RuleSetFetch{}}
	for i, cd := range c.Domains {
		d := strings.ToLower(cd.Name)
		if why, ok := taken[d]; ok {
			b.errorf("subscription.domains[%d]: %s: %s", i, d, why)
		} else if _, err := netip.ParseAddr(d); err == nil || !hostnameRe.MatchString(d) || len(d) > 253 {
			b.errorf("subscription.domains[%d]: %q isn't a domain", i, d)
		}
		taken[d] = "the site has it already"
		s.Domains = append(s.Domains, d)
		s.RuleSets[d] = b.ruleSetFetch(fmt.Sprintf("subscription.domains[%d]", i), d, cd.RuleSets, n)
	}
	if n != nil {
		n.ServesSubscription = true
		b.f.Subscription = s
	}
}

// ruleSetFetch is how profiles served under domain fetch their rule sets:
// as set, or directly when another node forwards domain to site, the
// subscription node, by passthrough. Such a relay is there to be reached
// directly, and the nodes behind the proxy may refuse its address, as one
// in a country they keep traffic out of. A passthrough of domain that
// can't reach site is an error, as it would send profiles' rule sets
// elsewhere; setting rule_sets takes the decision back.
func (b *builder) ruleSetFetch(where, domain, set string, site *Node) RuleSetFetch {
	switch set {
	case "direct":
		return RuleSetFetch{Direct: true, Set: true}
	case "proxy":
		return RuleSetFetch{Set: true}
	case "":
	default:
		b.errorf("%s.rule_sets: %q: want direct or proxy", where, set)
		return RuleSetFetch{}
	}
	if site == nil {
		return RuleSetFetch{}
	}
	var relay *Node
	for _, r := range b.f.Nodes {
		if r == site {
			continue
		}
		for _, pt := range r.Passthrough {
			if !strings.EqualFold(pt.Host, domain) {
				continue
			}
			if why := missesSite(pt.Target, site); why != "" {
				b.errorf("nodes.%s.passthrough.%s: %s, not to node %s, which serves the subscription site; if it reaches the site all the same, set %s.rule_sets to direct or proxy", r.Name, pt.Host, why, site.Name, where)
			}
			if relay == nil {
				relay = r
			}
		}
	}
	return RuleSetFetch{Direct: relay != nil, Relay: relay}
}

// missesSite says why target can't be site, or "" when it may be: a
// loopback address is the forwarding node itself, and an IP other than
// site's address, when that is one, another host. Names aren't resolved,
// and ports aren't compared, as one may be forwarded on the way.
func missesSite(target string, site *Node) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	if strings.EqualFold(host, "localhost") {
		return "it sends it to the node itself"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "it sends it to the node itself"
	}
	if addr, err := netip.ParseAddr(site.Address); err == nil && addr.Unmap() != ip.Unmap() {
		return "it sends it to " + target
	}
	return ""
}

// realityNames checks that the multiplexer leaves each node's Reality
// server name to Reality, since clients connect with it, and that the
// target isn't Reality itself.
func (b *builder) realityNames() {
	for _, n := range b.f.Nodes {
		if n.Reality == nil {
			continue
		}
		if loopsBack(n) {
			b.errorf("nodes.%s.reality.target: %s is the node's own Reality listener, which would hand the handshake back to itself; point it at a site", n.Name, net.JoinHostPort(n.Reality.TargetHost, strconv.Itoa(n.Reality.TargetPort)))
		}
		if !n.Mux() {
			continue
		}
		// Names match whatever their case, as in the multiplexer.
		taken := map[string]string{}
		for _, pt := range n.Passthrough {
			taken[strings.ToLower(pt.Host)] = "passthrough; drop that entry and set reality.target to " + pt.Target
		}
		if n.ServesSubscription {
			for _, d := range b.f.Subscription.Domains {
				taken[d] = "the subscription site; give one of them another name"
			}
		}
		if n.Naive != nil {
			taken[strings.ToLower(n.Naive.Domain)] = "naive; give one of them another name"
		}
		if to, ok := taken[strings.ToLower(n.Reality.ServerName)]; ok {
			b.errorf("nodes.%s.reality.server_name: the multiplexer sends %s to %s", n.Name, n.Reality.ServerName, to)
		}
	}
}

func (b *builder) client() {
	before := len(b.errs)
	b.f.Client = b.buildClient("client", b.cfg.Client)
	shared := map[string]bool{}
	for _, err := range b.errs[before:] {
		shared[err.Error()] = true
	}
	for _, u := range b.f.Users {
		u.Client = &b.f.Client
		if uc, _ := b.cfg.Users.Get(u.Name); uc.Client == nil {
			continue
		}
		where := "users." + u.Name + ".client"
		c, err := b.cfg.UserClient(u.Name)
		if err != nil {
			b.errorf("%s: %w", where, err)
			continue
		}
		start := len(b.errs)
		own := b.buildClient(where, c)
		// Drop what the override inherits from a broken client:.
		inherited := func(err error) bool { return shared[strings.Replace(err.Error(), where, "client", 1)] }
		b.errs = append(b.errs[:start], slices.DeleteFunc(b.errs[start:], inherited)...)
		u.Client = &own
	}
	reported := map[string]bool{}
	for _, u := range b.f.Users {
		b.unusableGroups(u)
		b.profileNames(u, reported)
	}
}

// profileNames checks that the label gives everything u is shown a name
// of its own: no two share links alike, and no member of the profile
// like one of its groups, their auto members or direct. One error per
// clash, however many users share the client.
func (b *builder) profileNames(u *User, reported map[string]bool) {
	where := "client"
	if u.Client != &b.f.Client {
		where = "users." + u.Name + ".client"
	}
	clash := func(id, name, other string) {
		msg := fmt.Sprintf("%s.label: %s is named %q, like %s; rename the group or change the label", where, id, name, other)
		if !reported[msg] {
			reported[msg] = true
			b.errorf("%s", msg)
		}
	}
	selectors := map[string]string{"direct": "direct"}
	for _, g := range u.Client.Groups {
		if !hasMembers(u, g) {
			continue // the profile leaves it out
		}
		selectors[g.Name] = "group " + g.Name
		if g.Auto {
			selectors[g.Name+"-auto"] = "the auto member of group " + g.Name
		}
	}
	links := map[string]string{}
	for _, n := range u.Nodes {
		offered := n.ClientProtocols()
		for _, p := range n.LinkProtocols() {
			id, name := MemberID(n, p), u.Client.Name(u, n, p)
			if other, ok := links[name]; ok {
				clash(id, name, other)
			} else {
				links[name] = id
			}
			if other, ok := selectors[name]; ok && slices.Contains(offered, p) {
				clash(id, name, other)
			}
		}
	}
}

// hasMembers reports whether u's profile has group g: some node of u's
// in it offers the profile a protocol.
func hasMembers(u *User, g Group) bool {
	return slices.ContainsFunc(u.Nodes, func(n *Node) bool { return g.Members.Matches(n) && len(n.ClientProtocols()) > 0 })
}

// unusableGroups reports the groups whose nodes of u's all serve only
// what the profile can't use, as reality over xhttp alone. Such a group
// gives way to its fallback and in the end to direct, like one without
// nodes, but u was given nodes for it: direct must be asked for, by a
// fallback that leads there or to a group u has members in.
func (b *builder) unusableGroups(u *User) {
	groups := map[string]Group{}
	for _, g := range u.Client.Groups {
		groups[g.Name] = g
	}
	for _, g := range u.Client.Groups {
		var unusable []string
		for _, n := range u.Nodes {
			if g.Members.Matches(n) && len(n.ClientProtocols()) == 0 {
				unusable = append(unusable, n.Name)
			}
		}
		if len(unusable) == 0 || hasMembers(u, g) {
			continue
		}
		// As the renderer resolves it; a loop ends nowhere.
		leads, next := false, g.Fallback
		for range len(groups) {
			to, ok := groups[next]
			leads = leads || next == "direct" || ok && hasMembers(u, to)
			next = to.Fallback
		}
		if !leads {
			b.errorf("users.%s: group %s has only nodes the profile can't use (%s), which serve no protocol %s speaks, and would go direct; give the user another node, or the group a fallback that leads to direct or to a group the user has nodes in",
				u.Name, g.Name, strings.Join(unusable, ", "), ClientEngine)
		}
	}
}

// buildClient checks a client: section, at where, and converts it.
func (b *builder) buildClient(where string, c config.Client) Client {
	var out Client
	groups := c.Groups.Keys()
	for name, g := range c.Groups.All() {
		w := where + ".groups." + name
		b.checkName(w, name)
		if name == "direct" {
			b.errorf("%s: \"direct\" is reserved", w)
		}
		sel, err := parseSelector(g.Nodes)
		if err != nil {
			b.errorf("%s.nodes: %w", w, err)
		}
		var relay *Selector
		if g.Relay != "" {
			switch r, err := parseSelector(g.Relay); {
			case err != nil:
				b.errorf("%s.relay: %w", w, err)
			case !slices.ContainsFunc(b.f.Nodes, func(n *Node) bool { return r.Matches(n) && len(n.Dials(ClientEngine)) > 0 }):
				b.errorf("%s.relay: no node with reality over a transport the profiles speak matches %s", w, g.Relay)
			default:
				relay = &r
			}
		}
		if g.Fallback != "" && g.Fallback != "direct" && (g.Fallback == name || !slices.Contains(groups, g.Fallback)) {
			b.errorf("%s.fallback: want direct or another group, got %q", w, g.Fallback)
		}
		def := cmp.Or(g.Default, "first")
		if g.Auto && g.Default == "" {
			def = "auto"
		}
		if g.Auto && slices.Contains(groups, name+"-auto") {
			b.errorf("%s.auto: its member is named %s-auto, like another group", w, name)
		}
		if def == "auto" && !g.Auto {
			b.errorf("%s.default: auto needs auto: true", w)
		}
		if def == "direct" && !g.IncludeDirect {
			b.errorf("%s.default: direct needs include_direct: true", w)
		}
		if !slices.Contains([]string{"first", "auto", "direct"}, def) && err == nil {
			if why := b.notMember(def, sel, relay); why != "" {
				b.errorf("%s.default: want first, auto, direct or a member of the group such as fr/reality or fr/reality@ru; %q %s", w, def, why)
			}
		}
		out.Groups = append(out.Groups, Group{
			Name:          name,
			Members:       sel,
			Relay:         relay,
			Default:       def,
			IncludeDirect: g.IncludeDirect,
			Auto:          g.Auto,
			Fallback:      g.Fallback,
		})
	}
	if c.DNS != nil {
		out.DNS = b.dns(where+".dns", c.DNS, groups)
	}
	// Client profiles sniff before any rule.
	out.Rules = b.rules(where+".rules", c.Rules, []string{ActionDirect, ActionReject}, groups, true)
	out.Log = b.logLevel(where+".log", c.Log)
	out.Label = b.label(where+".label", c.Label)
	out.IPv6 = c.IPv6
	out.Final = cmp.Or(c.Final, "direct")
	if out.Final != "direct" && !slices.Contains(groups, out.Final) {
		b.errorf("%s.final: want direct or a group, got %q", where, out.Final)
	}
	return out
}

// labelFieldRe finds the fields of a label, and what only looks like one.
var labelFieldRe = regexp.MustCompile(`\{[^{}]*\}`)

// label checks a label, DefaultLabel when unset.
func (b *builder) label(where, label string) string {
	if label == "" {
		return DefaultLabel
	}
	for _, field := range labelFieldRe.FindAllString(label, -1) {
		if !slices.Contains(LabelFields, strings.Trim(field, "{}")) {
			b.errorf("%s: unknown field %s; have {%s}", where, field, strings.Join(LabelFields, "}, {"))
		}
	}
	for _, field := range []string{"{node}", "{protocol}"} {
		if !strings.Contains(label, field) {
			b.errorf("%s: needs %s, to tell a node's protocols and the nodes apart", where, field)
		}
	}
	if strings.ContainsFunc(label, func(r rune) bool { return r == '@' || unicode.IsControl(r) }) {
		b.errorf("%s: can't have @, which names a relay, or control characters", where)
	}
	if label != strings.TrimSpace(label) {
		b.errorf("%s: can't start or end with a space", where)
	}
	return label
}

// notMember says why no user has id as a member of a group of members,
// offered through relays, or "" when those with its nodes do.
func (b *builder) notMember(id string, members Selector, relays *Selector) string {
	straight, via, relayed := strings.Cut(id, "@")
	name, protocol, ok := strings.Cut(straight, "/")
	if !ok {
		return "isn't <node>/<protocol>"
	}
	n, ok := b.f.nodes[name]
	switch {
	case !ok:
		return "names no node"
	case !members.Matches(n):
		return "is of a node the group's nodes leave out"
	case !slices.Contains(n.ClientProtocols(), protocol):
		return fmt.Sprintf("is no protocol node %s offers profiles (%s)", name, cmp.Or(strings.Join(n.ClientProtocols(), ", "), "none"))
	case !relayed:
		return ""
	}
	relay, ok := b.f.nodes[via]
	t, dials := n.Dial(ClientEngine)
	switch {
	case !ok:
		return "names no relay node"
	case relays == nil || !relays.Matches(relay) || len(relay.Dials(ClientEngine)) == 0:
		return "is through a node the group's relay leaves out"
	case relay == n:
		return "is through the node itself"
	case !dials || t.Protocol() != protocol:
		return fmt.Sprintf("isn't what a relay carries to node %s, %s", name, MemberID(n, t.Protocol()))
	}
	return ""
}

// logLevel checks a log level, LogWarn when unset.
func (b *builder) logLevel(where, level string) string {
	if level == "" {
		return LogWarn
	}
	if !slices.Contains(LogLevels, level) {
		b.errorf("%s: want one of %s, got %q", where, strings.Join(LogLevels, ", "), level)
	}
	return level
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

// kinds names transports as princo.yaml does.
func kinds(ts []Transport) string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Kind)
	}
	return strings.Join(out, " and ")
}

func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
