package singbox

import (
	"maps"
	"strconv"

	"github.com/dfjay/princo/internal/fleet"
)

// ruleSets collects the geosite/geoip rule sets rules refer to, in order of
// first use.
type ruleSets struct {
	tags []string
	seen map[string]bool
}

func (r *ruleSets) add(tag string) {
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	if !r.seen[tag] {
		r.seen[tag] = true
		r.tags = append(r.tags, tag)
	}
}

// ruleSetTag names the sing-box rule set for a geosite or geoip matcher, as
// published by SagerNet (geosite-<name>.srs, geoip-<name>.srs).
func ruleSetTag(m fleet.Matcher) string { return string(m.Kind) + "-" + m.Value }

// compileMatch turns ORed matchers into sing-box rule bodies. sing-box ANDs
// different fields of one rule (except the destination group: domains, IPs
// and rule sets), so matchers are split into one rule per field group; all
// of them get the same action.
func compileMatch(match []fleet.Matcher, sets *ruleSets) []map[string]any {
	dest := map[string]any{}
	var ports []any
	var networks []any
	appendTo := func(key string, v any) {
		list, _ := dest[key].([]any)
		dest[key] = append(list, v)
	}
	for _, m := range match {
		switch m.Kind {
		case fleet.MatchGeosite, fleet.MatchGeoIP:
			tag := ruleSetTag(m)
			sets.add(tag)
			appendTo("rule_set", tag)
		case fleet.MatchDomain:
			appendTo("domain", m.Value)
		case fleet.MatchDomainSuffix:
			appendTo("domain_suffix", m.Value)
		case fleet.MatchDomainKeyword:
			appendTo("domain_keyword", m.Value)
		case fleet.MatchIP:
			if m.Value == "private" {
				dest["ip_is_private"] = true
			} else {
				appendTo("ip_cidr", m.Value)
			}
		case fleet.MatchPort:
			p, _ := strconv.Atoi(m.Value)
			ports = append(ports, p)
		case fleet.MatchNetwork:
			networks = append(networks, m.Value)
		}
	}
	var out []map[string]any
	if len(dest) > 0 {
		out = append(out, dest)
	}
	if len(ports) > 0 {
		out = append(out, map[string]any{"port": ports})
	}
	for _, n := range networks {
		out = append(out, map[string]any{"network": n})
	}
	if len(out) == 0 {
		out = append(out, map[string]any{})
	}
	return out
}

// withAction returns the rule bodies with fields merged into each.
func withAction(bodies []map[string]any, fields map[string]any) []any {
	out := make([]any, 0, len(bodies))
	for _, body := range bodies {
		rule := maps.Clone(body)
		maps.Copy(rule, fields)
		out = append(out, rule)
	}
	return out
}

// ipOnly keeps the matchers that test destination addresses.
func ipOnly(match []fleet.Matcher) []fleet.Matcher {
	var out []fleet.Matcher
	for _, m := range match {
		if m.IsIP() {
			out = append(out, m)
		}
	}
	return out
}
