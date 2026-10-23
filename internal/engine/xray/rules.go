package xray

import (
	"strings"

	"github.com/dfjay/princo/internal/fleet"
)

// privateCIDRs is ip:private: the private, loopback, link-local and other
// reserved ranges, written out so the node's geoip data needn't have them.
var privateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// compileMatch turns ORed matchers into xray rules to outbound tag. xray
// ANDs the fields of a rule, so each field gets a rule of its own.
func compileMatch(match []fleet.Matcher, tag string) []any {
	domains := domainsOf(match)
	var ips, ports, networks, protocols []string
	for _, m := range match {
		switch m.Kind {
		case fleet.MatchGeoIP:
			ips = append(ips, "geoip:"+m.Value)
		case fleet.MatchIP:
			if m.Value == "private" {
				ips = append(ips, privateCIDRs...)
			} else {
				ips = append(ips, m.Value)
			}
		case fleet.MatchPort:
			ports = append(ports, m.Value)
		case fleet.MatchNetwork:
			networks = append(networks, m.Value)
		case fleet.MatchProtocol:
			protocols = append(protocols, m.Value)
		}
	}
	var out []any
	add := func(field string, value any) {
		out = append(out, map[string]any{field: value, "outboundTag": tag})
	}
	if len(domains) > 0 {
		add("domain", domains)
	}
	if len(ips) > 0 {
		add("ip", ips)
	}
	if len(ports) > 0 {
		add("port", strings.Join(ports, ","))
	}
	if len(networks) > 0 {
		add("network", strings.Join(networks, ","))
	}
	if len(protocols) > 0 {
		add("protocol", protocols)
	}
	return out
}

// domainsOf is the domain matchers in xray's syntax.
func domainsOf(match []fleet.Matcher) []string {
	var out []string
	for _, m := range match {
		switch m.Kind {
		case fleet.MatchGeosite:
			out = append(out, "geosite:"+m.Value)
		case fleet.MatchDomain:
			out = append(out, "full:"+m.Value)
		case fleet.MatchDomainSuffix:
			out = append(out, "domain:"+m.Value)
		case fleet.MatchDomainKeyword:
			out = append(out, "keyword:"+m.Value)
		}
	}
	return out
}
