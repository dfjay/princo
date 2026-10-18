package singbox

import "github.com/dfjay/princo/internal/fleet"

// renderDNSServer renders one server; detour is the outbound its queries
// go through ("" for direct).
func renderDNSServer(s fleet.DNSServer, detour string) map[string]any {
	out := map[string]any{
		"tag":    s.Name,
		"type":   s.Type,
		"server": s.Server,
	}
	if s.Port != 0 {
		out["server_port"] = s.Port
	}
	if s.Path != "" {
		out["path"] = s.Path
	}
	if detour != "" {
		out["detour"] = detour
	}
	if s.Resolver != "" {
		out["domain_resolver"] = s.Resolver
	}
	return out
}

// renderDNS renders a resolver. detourOf maps a server to its outbound;
// aaaaBlocked reports servers whose path can't carry IPv6, for which AAAA
// queries are answered empty instead.
func renderDNS(d *fleet.DNS, sets *ruleSets, detourOf func(fleet.DNSServer) string, aaaaBlocked func(server string) bool) map[string]any {
	servers := make([]any, 0, len(d.Servers))
	for _, s := range d.Servers {
		servers = append(servers, renderDNSServer(s, detourOf(s)))
	}
	out := map[string]any{
		"servers": servers,
		"final":   d.Final,
	}
	var rules []any
	for _, r := range d.Rules {
		bodies := compileMatch(r.Match, sets)
		if aaaaBlocked(r.Server) {
			rules = append(rules, withAction(bodies, map[string]any{
				"query_type": []any{"AAAA"},
				"action":     "predefined",
			})...)
		}
		rules = append(rules, withAction(bodies, map[string]any{
			"action": "route",
			"server": r.Server,
		})...)
	}
	if len(rules) > 0 {
		out["rules"] = rules
	}
	if d.Strategy != "" {
		out["strategy"] = d.Strategy
	}
	if d.Optimistic {
		out["optimistic"] = true
	}
	return out
}
