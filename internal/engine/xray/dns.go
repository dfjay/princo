package xray

import (
	"cmp"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/dfjay/princo/internal/fleet"
)

// dnsTag marks the resolver's own queries, which go out directly.
const dnsTag = "dns"

// renderDNS renders a node's resolver. xray has no resolver per server,
// so the system resolves their host names.
func renderDNS(d *fleet.DNS) map[string]any {
	server := func(name string) map[string]any {
		i := slices.IndexFunc(d.Servers, func(s fleet.DNSServer) bool { return s.Name == name })
		return dnsServer(d.Servers[i])
	}
	var servers []any
	for _, r := range d.Rules {
		s := server(r.Server)
		s["domains"] = domainsOf(r.Match)
		// These domains only, and only here.
		s["skipFallback"] = true
		s["finalQuery"] = true
		servers = append(servers, s)
	}
	servers = append(servers, server(d.Final))
	out := map[string]any{"servers": servers, "tag": dnsTag}
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

// dnsServer is a server in xray's syntax, but for tls, which fleet.Build
// refuses.
func dnsServer(s fleet.DNSServer) map[string]any {
	if s.Type == "udp" {
		out := map[string]any{"address": s.Server}
		if s.Port != 0 {
			out["port"] = s.Port
		}
		return out
	}
	host := s.Server
	if s.Port != 0 {
		host = net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	var address string
	switch s.Type {
	case "tcp":
		address = "tcp+local://" + host
	case "https":
		address = "https+local://" + host + cmp.Or(s.Path, "/dns-query")
	default: // quic
		address = "quic+local://" + host
	}
	return map[string]any{"address": address}
}
