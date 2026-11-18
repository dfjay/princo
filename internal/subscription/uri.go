// Package subscription builds what users import into their apps.
package subscription

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/dfjay/princo/internal/fleet"
)

// URIs returns the share links for user, one per node and protocol in the
// user's node order; the universal subscription is these, one per line.
func URIs(u *fleet.User) []string {
	var out []string
	for _, n := range u.Nodes {
		addr := net.JoinHostPort(n.Address, "443")
		// A link's name is a URI component: apps differ in what they make
		// of a literal +, & or /, so only unreserved characters stay.
		name := func(protocol string) string {
			return strings.ReplaceAll(url.QueryEscape(u.Client.Name(u, n, protocol)), "+", "%20")
		}
		if r := n.Reality; r != nil {
			// What every transport's link ends with.
			reality := fmt.Sprintf("security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s", r.ServerName, r.PublicKey, r.ShortID)
			for _, t := range r.Transports {
				var q string
				switch t.Kind {
				case fleet.TransportTCP:
					q = "flow=xtls-rprx-vision&type=tcp"
				case fleet.TransportGRPC:
					q = "type=grpc&serviceName=" + url.QueryEscape(t.ServiceName) + "&mode=gun"
				case fleet.TransportXHTTP:
					q = "type=xhttp&path=" + url.QueryEscape(t.Path) + "&mode=" + t.Mode
				default:
					continue
				}
				out = append(out, fmt.Sprintf("vless://%s@%s?encryption=none&%s&%s#%s", u.UUID, addr, q, reality, name(t.Protocol())))
			}
		}
		if h := n.Hysteria2; h != nil {
			q := "sni=" + url.QueryEscape(n.Address)
			if h.Obfs != "" {
				q += "&obfs=" + h.Obfs + "&obfs-password=" + url.QueryEscape(h.ObfsPassword)
			}
			out = append(out, fmt.Sprintf("hysteria2://%s@%s/?%s#%s", u.UUID, addr, q, name("hysteria2")))
		}
		if nv := n.Naive; nv != nil {
			out = append(out, fmt.Sprintf("naive+https://%s@%s:443#%s",
				url.UserPassword(u.Name, u.UUID), nv.Domain, name("naive")))
		}
	}
	return out
}
