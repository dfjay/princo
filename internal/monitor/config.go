// Package monitor is what a node checks about itself on a timer: that its
// engine runs, its certificates aren't about to expire, WARP passes traffic
// and, from the nodes told to, that the other nodes answer. It tells a
// Telegram chat when a check changes state.
package monitor

// Config is the node's monitor.json, rendered with its other files. It
// holds secrets: Telegram's token and the engine's API secret.
type Config struct {
	Node         string        `json:"node"`
	Telegram     Telegram      `json:"telegram"`
	Unit         string        `json:"unit"`
	Certificates []Certificate `json:"certificates"`
	// Warp is nil where the node has no WARP to check.
	Warp  *Warp    `json:"warp,omitzero"`
	Reach []Target `json:"reach"`
}

type Telegram struct {
	// API is the Bot API's base URL, e.g. https://api.telegram.org.
	API   string `json:"api"`
	Token string `json:"token"`
	Chat  string `json:"chat"`
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
