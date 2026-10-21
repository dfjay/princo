package xray

import (
	"maps"
	"strings"

	"github.com/dfjay/princo/internal/fleet"
)

// compileMatch turns ORed matchers into xray rule bodies. xray ANDs the
// fields of a rule, so each field gets a rule of its own; all of them get
// the same outbound.
func compileMatch(match []fleet.Matcher) []map[string]any {
	var domains, ips, ports, networks []string
	for _, m := range match {
		switch m.Kind {
		case fleet.MatchGeosite:
			domains = append(domains, "geosite:"+m.Value)
		case fleet.MatchDomain:
			domains = append(domains, "full:"+m.Value)
		case fleet.MatchDomainSuffix:
			domains = append(domains, "domain:"+m.Value)
		case fleet.MatchDomainKeyword:
			domains = append(domains, "keyword:"+m.Value)
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
	var out []map[string]any
	if len(domains) > 0 {
		out = append(out, map[string]any{"domain": domains})
	}
	if len(ips) > 0 {
		out = append(out, map[string]any{"ip": ips})
	}
	if len(ports) > 0 {
		out = append(out, map[string]any{"port": strings.Join(ports, ",")})
	}
	if len(networks) > 0 {
		out = append(out, map[string]any{"network": strings.Join(networks, ",")})
	}
	return out
}

// withOutbound returns the rule bodies, each sent to tag.
func withOutbound(bodies []map[string]any, tag string) []any {
	out := make([]any, 0, len(bodies))
	for _, body := range bodies {
		rule := maps.Clone(body)
		rule["outboundTag"] = tag
		out = append(out, rule)
	}
	return out
}
