// Package subscription builds what users import into their apps.
package subscription

import (
	"fmt"
	"net"
	"net/url"

	"github.com/dfjay/princo/internal/fleet"
)

// URIs returns the share links for user, one per node and protocol in the
// user's node order; the universal subscription is these, one per line.
func URIs(u *fleet.User) []string {
	var out []string
	for _, n := range u.Nodes {
		addr := net.JoinHostPort(n.Address, "443")
		name := func(protocol string) string {
			return (&url.URL{Fragment: u.Name + "-" + n.Name + "-" + protocol}).EscapedFragment()
		}
		if r := n.Reality; r != nil {
			out = append(out, fmt.Sprintf(
				"vless://%s@%s?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s#%s",
				u.UUID, addr, r.ServerName, r.PublicKey, r.ShortID, name("reality")))
			if x := n.XHTTP; x != nil {
				out = append(out, fmt.Sprintf(
					"vless://%s@%s?encryption=none&type=xhttp&path=%s&mode=%s&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s#%s",
					u.UUID, addr, url.QueryEscape(x.Path), x.Mode, r.ServerName, r.PublicKey, r.ShortID, name("xhttp")))
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
