// Package subscription builds what users import into their apps.
package subscription

import (
	"fmt"
	"net/url"

	"github.com/dfjay/princo/internal/fleet"
)

// URIs returns the share links for user, one per node and protocol in the
// user's node order; the universal subscription is these, one per line.
func URIs(u *fleet.User) []string {
	var out []string
	for _, n := range u.Nodes {
		name := func(protocol string) string { return u.Name + "-" + n.Name + "-" + protocol }
		if r := n.Reality; r != nil {
			out = append(out, fmt.Sprintf(
				"vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s#%s",
				u.UUID, n.Address, r.ServerName, r.PublicKey, r.ShortID, name("reality")))
		}
		if h := n.Hysteria2; h != nil {
			out = append(out, fmt.Sprintf("hysteria2://%s@%s:443?sni=%s&obfs=salamander&obfs-password=%s#%s",
				u.UUID, n.Address, n.Address, url.QueryEscape(h.ObfsPassword), name("hy2")))
		}
		if nv := n.Naive; nv != nil {
			out = append(out, fmt.Sprintf("naive+https://%s:%s@%s:443#%s", u.Name, u.UUID, nv.Domain, name("naive")))
		}
	}
	return out
}
