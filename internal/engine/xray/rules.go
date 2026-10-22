package xray

import (
	"slices"
	"strings"

	"github.com/dfjay/princo/internal/fleet"
)

// compileMatch turns ORed matchers into xray rules to outbound tag. xray
// ANDs the fields of a rule, so each field gets a rule of its own.
func compileMatch(match []fleet.Matcher, tag string) []any {
	domains := domainsOf(match)
	var ips, ports, networks []string
	for _, m := range match {
		switch m.Kind {
		case fleet.MatchGeoIP:
			ips = append(ips, "geoip:"+m.Value)
		case fleet.MatchIP:
			if m.Value == "private" {
				ips = append(ips, "geoip:private")
			} else {
				ips = append(ips, m.Value)
			}
		case fleet.MatchPort:
			ports = append(ports, m.Value)
		case fleet.MatchNetwork:
			networks = append(networks, m.Value)
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

func matchesIP(r fleet.Rule) bool {
	return slices.ContainsFunc(r.Match, fleet.Matcher.IsIP)
}
