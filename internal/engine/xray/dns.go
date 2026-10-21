package xray

import (
	"cmp"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/dfjay/princo/internal/fleet"
)

// renderDNS renders a node's resolver. Servers are queried directly, as
// on sing-box nodes; xray has no resolver per server, so the system
// resolves their host names.
func renderDNS(d *fleet.DNS) map[string]any {
	server := func(name string) fleet.DNSServer {
		i := slices.IndexFunc(d.Servers, func(s fleet.DNSServer) bool { return s.Name == name })
		return d.Servers[i]
	}
	var servers []any
	for _, r := range d.Rules {
		servers = append(servers, map[string]any{
			"address":      dnsAddress(server(r.Server)),
			"domains":      domainsOf(r.Match),
			"skipFallback": true,
		})
	}
	servers = append(servers, dnsAddress(server(d.Final)))
	out := map[string]any{"servers": servers}
	switch d.Strategy {
	case "ipv4_only":
		out["queryStrategy"] = "UseIPv4"
	case "ipv6_only":
		out["queryStrategy"] = "UseIPv6"
	}
	if d.Optimistic {
		out["serveStale"] = true
	}
	return out
}

// dnsAddress is a server's address in xray's syntax, but for tls, which
// fleet.Build refuses.
func dnsAddress(s fleet.DNSServer) string {
	host := s.Server
	if s.Port != 0 {
		host = net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	}
	if s.Type == "udp" {
		return host
	}
	if s.Port == 0 && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	switch s.Type {
	case "tcp":
		return "tcp+local://" + host
	case "https":
		return "https+local://" + host + cmp.Or(s.Path, "/dns-query")
	default: // quic
		return "quic+local://" + host
	}
}
