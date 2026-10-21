package xray

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

// xhttpSocket is where the Reality inbound falls back to for XHTTP.
const xhttpSocket = "@princo-xhttp"

const vision = "xtls-rprx-vision"

// RenderServer renders the xray config of one node.
func (e *Engine) RenderServer(f *fleet.Fleet, name string) ([]byte, error) {
	n, ok := f.Node(name)
	if !ok {
		return nil, fmt.Errorf("no node named %q", name)
	}
	cfg := map[string]any{
		"version":   map[string]any{"min": minVersion},
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  serverInbounds(f, n),
		"outbounds": serverOutbounds(n),
	}
	var rules []any
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
		cfg["routing"] = map[string]any{"rules": rules}
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// serverInbounds needs n.Reality: fleet.Build refuses xray nodes without.
func serverInbounds(f *fleet.Fleet, n *fleet.Node) []any {
	r := n.Reality
	users := f.UsersOf(n)
	var sniffing map[string]any
	if slices.ContainsFunc(n.Rules, func(r fleet.Rule) bool { return r.Action == fleet.ActionSniff }) {
		sniffing = map[string]any{
			"enabled":      true,
			"destOverride": []any{"http", "tls", "quic"},
			"routeOnly":    true,
		}
	}

	clients := make([]any, 0, len(users))
	for _, u := range users {
		clients = append(clients, map[string]any{"id": u.UUID, "email": u.Name, "flow": vision})
	}
	// Chain hops that exit here log in like users, as no user can be named.
	for _, m := range f.ChainsInto(n) {
		clients = append(clients, map[string]any{"id": m.ChainUUID, "email": "chain:" + m.Name, "flow": vision})
	}
	settings := map[string]any{"clients": clients, "decryption": "none"}
	if n.XHTTP != nil {
		settings["fallbacks"] = []any{map[string]any{"dest": xhttpSocket}}
	}
	listen, port := "::", 443
	if n.Mux() {
		listen, port = "127.0.0.1", engine.MuxRealityPort
	}
	reality := map[string]any{
		"tag":      "vless-reality-in",
		"listen":   listen,
		"port":     port,
		"protocol": "vless",
		"settings": settings,
		"streamSettings": map[string]any{
			"network":  "raw",
			"security": "reality",
			"realitySettings": map[string]any{
				"target":      r.ServerName + ":443",
				"serverNames": []any{r.ServerName},
				"privateKey":  r.PrivateKey,
				"shortIds":    []any{r.ShortID},
			},
		},
	}
	if sniffing != nil {
		reality["sniffing"] = sniffing
	}
	out := []any{reality}

	if x := n.XHTTP; x != nil {
		clients := make([]any, 0, len(users))
		for _, u := range users {
			clients = append(clients, map[string]any{"id": u.UUID, "email": u.Name})
		}
		in := map[string]any{
			"tag":      "vless-xhttp-in",
			"listen":   xhttpSocket,
			"protocol": "vless",
			"settings": map[string]any{"clients": clients, "decryption": "none"},
			"streamSettings": map[string]any{
				"network":       "xhttp",
				"xhttpSettings": map[string]any{"path": x.Path},
			},
		}
		if sniffing != nil {
			in["sniffing"] = sniffing
		}
		out = append(out, in)
	}
	return out
}

// serverOutbounds puts the egress first: xray sends what no rule matches
// to the first outbound.
func serverOutbounds(n *fleet.Node) []any {
	direct := map[string]any{"protocol": "freedom", "tag": "direct"}
	var ip string
	if n.DNS != nil {
		// Resolve with the node's DNS rather than the system's.
		ip = ipStrategy(n.DNS.Strategy)
		direct["settings"] = map[string]any{"domainStrategy": "Use" + ip}
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

// realityOutbound connects to up's VLESS-Reality inbound as uuid.
func realityOutbound(up *fleet.Node, uuid string) map[string]any {
	r := up.Reality
	return map[string]any{
		"protocol": "vless",
		"tag":      up.Name + "-reality",
		"settings": map[string]any{
			"address":    up.Address,
			"port":       443,
			"id":         uuid,
			"encryption": "none",
			"flow":       vision,
		},
		"streamSettings": map[string]any{
			"network":  "raw",
			"security": "reality",
			"realitySettings": map[string]any{
				"serverName":  r.ServerName,
				"fingerprint": "chrome",
				"publicKey":   r.PublicKey,
				"shortId":     r.ShortID,
			},
		},
	}
}

func warpOutbound(w *fleet.Warp) map[string]any {
	return map[string]any{
		"protocol": "wireguard",
		"tag":      "warp",
		"settings": map[string]any{
			"secretKey": w.PrivateKey,
			"address":   []any{w.IPv4, w.IPv6},
			"peers": []any{map[string]any{
				"publicKey":  engine.WarpPeerPublicKey,
				"endpoint":   engine.WarpPeer + ":" + strconv.Itoa(engine.WarpPeerPort),
				"allowedIPs": []any{"0.0.0.0/0", "::/0"},
			}},
			"mtu": 1280,
			// gVisor's netstack: no TUN device or routes on the host.
			"noKernelTun": true,
		},
	}
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
