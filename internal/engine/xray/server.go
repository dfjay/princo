package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

// fallbackSocket, with a transport's kind, is where the Reality inbound
// falls back to for the transport beside tcp.
const fallbackSocket = "@princo-"

const vision = "xtls-rprx-vision"

// RenderServer renders the xray config of one node.
func (e *Engine) RenderServer(f *fleet.Fleet, name string) ([]byte, error) {
	n, ok := f.Node(name)
	if !ok {
		return nil, fmt.Errorf("no node named %q", name)
	}
	if err := checkReality(n); err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"version":   map[string]any{"min": minVersion},
		"log":       renderLog(n.Log),
		"inbounds":  serverInbounds(f, n),
		"outbounds": serverOutbounds(f, n),
	}
	// Each user of the monitor's proxy leaves through their node, and
	// nothing else from it anywhere.
	var rules []any
	for _, up := range n.MonitorVia {
		rules = append(rules, map[string]any{"inboundTag": []any{engine.MonitorInbound}, "user": []any{up.Name}, "outboundTag": engine.MonitorTag(up)})
	}
	if len(rules) > 0 {
		rules = append(rules, map[string]any{"inboundTag": []any{engine.MonitorInbound}, "outboundTag": "block"})
	}
	// Other nodes' reports leave directly: a stalled WARP, or a chain back
	// to their node, would keep them in.
	if reporters := engine.MonitorAccounts(f, n); len(reporters) > 0 {
		rules = append(rules, map[string]any{"user": reporters, "outboundTag": "direct"})
	}
	if n.DNS != nil {
		cfg["dns"] = renderDNS(n.DNS)
		rules = append(rules, map[string]any{"inboundTag": []any{dnsTag}, "outboundTag": "direct"})
	}
	for _, r := range n.Rules {
		if r.Action == fleet.ActionSniff {
			continue // the inbounds sniff
		}
		tag := "direct"
		if r.Action == fleet.ActionReject {
			tag = "block"
		}
		rules = append(rules, compileMatch(r.Match, tag)...)
	}
	if len(rules) > 0 {
		routing := map[string]any{"rules": rules}
		if slices.ContainsFunc(n.Rules, func(r fleet.Rule) bool { return slices.ContainsFunc(r.Match, fleet.Matcher.IsIP) }) {
			// IP rules see domains' addresses, resolved as rules are matched in
			// order; connections still go to the domain.
			routing["domainStrategy"] = "IPOnDemand"
		}
		cfg["routing"] = routing
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// serverInbounds needs n.Reality: fleet.Build refuses xray nodes without.
// Its first transport takes the port and the Reality handshake; one beside
// it gets what isn't the first's by fallback, already out of TLS.
func serverInbounds(f *fleet.Fleet, n *fleet.Node) []any {
	r := n.Reality
	var sniffing map[string]any
	if slices.ContainsFunc(n.Rules, func(r fleet.Rule) bool { return r.Action == fleet.ActionSniff }) {
		sniffing = map[string]any{
			"enabled":      true,
			"destOverride": []any{"http", "tls", "quic"},
			"routeOnly":    true,
		}
	}
	inbound := func(tag string, t fleet.Transport) map[string]any {
		accounts := f.Accounts(n, t)
		clients := make([]any, 0, len(accounts))
		for _, a := range accounts {
			c := map[string]any{"id": a.UUID, "email": a.Name}
			if t.Vision() {
				c["flow"] = vision
			}
			clients = append(clients, c)
		}
		in := map[string]any{
			"tag":            tag,
			"protocol":       "vless",
			"settings":       map[string]any{"clients": clients, "decryption": "none"},
			"streamSettings": transportStream(t, false),
		}
		if sniffing != nil {
			in["sniffing"] = sniffing
		}
		return in
	}

	front := inbound("vless-reality-in", r.Transports[0])
	stream := front["streamSettings"].(map[string]any)
	stream["security"] = "reality"
	stream["realitySettings"] = map[string]any{
		"target":      net.JoinHostPort(r.TargetHost, strconv.Itoa(r.TargetPort)),
		"serverNames": []any{r.ServerName},
		"privateKey":  r.PrivateKey,
		"shortIds":    []any{r.ShortID},
	}
	front["listen"], front["port"] = "::", 443
	if n.Mux() {
		// At 127.0.0.1 and ::1 only: xray binds an inbound to an
		// interface only through a raw SO_BINDTODEVICE.
		front["port"] = engine.MuxRealityPort
		stream["sockopt"] = map[string]any{"customSockopt": []any{map[string]any{
			"system":  "linux",
			"network": "tcp",
			// Linux's SOL_SOCKET and SO_BINDTODEVICE, wherever it renders.
			"level": "1",
			"opt":   "25",
			"type":  "str",
			"value": engine.LoopbackInterface,
		}}}
	}
	out := []any{front}
	if len(r.Transports) == 2 {
		t := r.Transports[1]
		socket := fallbackSocket + t.Kind
		front["settings"].(map[string]any)["fallbacks"] = []any{map[string]any{"dest": socket}}
		behind := inbound("vless-"+t.Kind+"-in", t)
		behind["listen"] = socket
		out = append(out, behind)
	}
	if via := n.MonitorVia; len(via) > 0 {
		accounts := make([]any, 0, len(via))
		for _, up := range via {
			accounts = append(accounts, map[string]any{"user": up.Name, "pass": n.MonitorUUID})
		}
		out = append(out, map[string]any{
			"tag":      engine.MonitorInbound,
			"listen":   "127.0.0.1",
			"port":     engine.MonitorPort,
			"protocol": "socks",
			"settings": map[string]any{"auth": "password", "accounts": accounts, "udp": false},
		})
	}
	return out
}

// serverOutbounds puts the egress first: xray sends what no rule matches
// to the first outbound. The monitor's outbounds come last.
func serverOutbounds(f *fleet.Fleet, n *fleet.Node) []any {
	out := egressOutbounds(n)
	for _, up := range n.MonitorVia {
		o := realityOutbound(up, n.MonitorUUID)
		o["tag"] = engine.MonitorTag(up)
		out = append(out, o)
	}
	return out
}

func egressOutbounds(n *fleet.Node) []any {
	direct := map[string]any{"protocol": "freedom", "tag": "direct"}
	var ip string
	if n.DNS != nil {
		// Resolve with the node's DNS rather than the system's.
		ip = ipStrategy(n.DNS.Strategy)
		direct["streamSettings"] = map[string]any{"sockopt": map[string]any{"domainStrategy": "Use" + ip}}
	}
	block := map[string]any{"protocol": "blackhole", "tag": "block"}
	switch n.Egress.Kind {
	case fleet.EgressWarp:
		warp := warpOutbound(n.Warp)
		if ip != "" {
			warp["targetStrategy"] = "Force" + ip
		}
		return []any{warp, direct, block}
	case fleet.EgressNode:
		return []any{realityOutbound(n.Egress.Node, n.ChainUUID), direct, block}
	default:
		return []any{direct, block}
	}
}

// transports are the streamSettings of each kind, without their security;
// client adds what only the connecting side sets.
var transports = map[string]func(t fleet.Transport, client bool) map[string]any{
	fleet.TransportTCP: func(fleet.Transport, bool) map[string]any {
		return map[string]any{"network": "raw"}
	},
	fleet.TransportGRPC: func(t fleet.Transport, _ bool) map[string]any {
		return map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": t.ServiceName}}
	},
	fleet.TransportXHTTP: func(t fleet.Transport, client bool) map[string]any {
		settings := map[string]any{"path": t.Path}
		if client {
			settings["mode"] = t.Mode
		}
		return map[string]any{"network": "xhttp", "xhttpSettings": settings}
	},
}

// transportStream renders t, which checkReality saw is one of transports.
func transportStream(t fleet.Transport, client bool) map[string]any {
	return transports[t.Kind](t, client)
}

// checkReality refuses what the renderer would make something else of: n
// without transports xray serves together, or a node n connects to by
// none. fleet.Build lets none through, so this is for a fleet built
// otherwise, or a transport fleet lists for xray before transports has it.
func checkReality(n *fleet.Node) error {
	renders := func(m *fleet.Node, ts []fleet.Transport) error {
		if len(ts) == 0 {
			return fmt.Errorf("node %s: no reality transport xray speaks", m.Name)
		}
		for _, t := range ts {
			if transports[t.Kind] == nil {
				return fmt.Errorf("node %s: xray renders no reality transport %q", m.Name, t.Kind)
			}
		}
		return nil
	}
	if n.Reality == nil {
		return fmt.Errorf("node %s: xray needs reality", n.Name)
	}
	if err := renders(n, n.Reality.Transports); err != nil {
		return err
	}
	if !fleet.ServesTogether(engineName, n.Reality.Transports) {
		return fmt.Errorf("node %s: xray doesn't serve its %d reality transports on one port", n.Name, len(n.Reality.Transports))
	}
	for _, up := range n.Upstreams() {
		if err := renders(up, up.Dials(engineName)); err != nil {
			return err
		}
	}
	return nil
}

// realityOutbound connects n to up's VLESS-Reality inbound as uuid, by the
// transport of up's that xray takes: fleet.Build checked there is one.
func realityOutbound(up *fleet.Node, uuid string) map[string]any {
	r := up.Reality
	t, _ := up.Dial(engineName)
	settings := map[string]any{
		"address":    up.Address,
		"port":       443,
		"id":         uuid,
		"encryption": "none",
	}
	if t.Vision() {
		settings["flow"] = vision
	}
	stream := transportStream(t, true)
	stream["security"] = "reality"
	stream["realitySettings"] = map[string]any{
		"serverName":  r.ServerName,
		"fingerprint": "chrome",
		"publicKey":   r.PublicKey,
		"shortId":     r.ShortID,
	}
	return map[string]any{
		"protocol":       "vless",
		"tag":            fleet.MemberID(up, t.Protocol()),
		"settings":       settings,
		"streamSettings": stream,
	}
}

func warpOutbound(w *fleet.Warp) map[string]any {
	settings := map[string]any{
		"secretKey": w.PrivateKey,
		"address":   []any{w.IPv4, w.IPv6},
		"peers": []any{map[string]any{
			"publicKey":  engine.WarpPeerPublicKey,
			"endpoint":   net.JoinHostPort(w.Host, strconv.Itoa(w.Port)),
			"allowedIPs": []any{"0.0.0.0/0", "::/0"},
		}},
		"mtu": 1280,
		// gVisor's netstack: no TUN device or routes on the host.
		"noKernelTun": true,
	}
	if w.Reserved != nil {
		settings["reserved"] = w.Reserved
	}
	return map[string]any{"protocol": "wireguard", "tag": "warp", "settings": settings}
}

// ipStrategy is the address families a DNS strategy resolves, as xray's
// domain strategies (UseIPv4v6, ForceIPv4v6, ...) end.
func ipStrategy(strategy string) string {
	switch strategy {
	case "prefer_ipv4":
		return "IPv4v6"
	case "prefer_ipv6":
		return "IPv6v4"
	case "ipv4_only":
		return "IPv4"
	case "ipv6_only":
		return "IPv6"
	default:
		return "IP"
	}
}

// renderLog renders a fleet log level in xray's names. none also drops
// the access log.
func renderLog(level string) map[string]any {
	switch level {
	case fleet.LogWarn:
		return map[string]any{"loglevel": "warning"}
	case fleet.LogNone:
		return map[string]any{"loglevel": "none", "access": "none"}
	default:
		return map[string]any{"loglevel": level}
	}
}
