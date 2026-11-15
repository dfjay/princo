// Package monitor is what a node checks about itself on a timer: that its
// engine runs, its certificates aren't about to expire, WARP passes traffic
// and, from the nodes told to, that the other nodes answer. It tells the
// channels of monitor.notify when a check changes state.
package monitor

import "net/url"

// Config is the node's monitor.json, rendered with its other files. It
// holds secrets: the channels' and the engine's API secret.
type Config struct {
	Node string `json:"node"`
	// Notify are the channels to tell, sorted by name.
	Notify          []Channel     `json:"notify"`
	Confirm         int           `json:"confirm"`
	CertificateDays int           `json:"certificate_days"`
	Unit            string        `json:"unit"`
	Certificates    []Certificate `json:"certificates"`
	// Warp is nil where the node has no WARP to check.
	Warp  *Warp    `json:"warp,omitzero"`
	Reach []Target `json:"reach"`
	// Proxy is nil where every channel is told directly.
	Proxy *Proxy `json:"proxy,omitzero"`
}

// Proxy is the engine's SOCKS proxy at Address, for the channels the node
// can't reach. A connection leaves through the node its user names.
type Proxy struct {
	Address  string `json:"address"`
	Password string `json:"password"`
}

// URL is the proxy as node's user. The name goes to it unresolved: the
// node's own DNS may lie about a channel it can't reach.
func (p *Proxy) URL(node string) *url.URL {
	return &url.URL{Scheme: "socks5h", User: url.UserPassword(node, p.Password), Host: p.Address}
}

type Certificate struct {
	Name string `json:"name"`
	// File is its chain in PEM, the leaf first.
	File string `json:"file"`
}

// Warp is checked through the engine's API at URL.
type Warp struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
	// Outbound is WARP's tag in the engine.
	Outbound string `json:"outbound"`
}

// Target is a node's TCP port to connect to.
type Target struct {
	Node    string `json:"node"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	// ServerName, when set, is the name to complete a TLS handshake with,
	// as a client's first packets would.
	ServerName string `json:"server_name,omitempty"`
}
