// Package engine defines the contract every supported VPN engine (sing-box,
// xray, ...) implements, plus a registry for looking them up by name.
package engine

import (
	"fmt"
	"sync"

	"github.com/dfjay/princo/internal/fleet"
)

// Where a rendered server config expects things on the host. Whatever
// deploys the node (the NixOS module, princo deploy) puts them there.
const (
	// RuleSetDir holds the geosite/geoip rule sets in the engine's format:
	// one <tag>.srs each for sing-box, geosite.dat and geoip.dat for xray.
	RuleSetDir = "/var/lib/princo/rules"
	// CertDir holds one directory per domain with fullchain.pem and key.pem.
	CertDir = "/var/lib/princo/certs"
	// MuxRealityPort and MuxNaivePort are the loopback ports behind the
	// SNI multiplexer on TCP 443.
	MuxRealityPort = 8444
	MuxNaivePort   = 8445
)

// Cloudflare WARP's WireGuard peer.
const (
	WarpPeer          = "engage.cloudflareclient.com"
	WarpPeerPort      = 2408
	WarpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

// ClientEngine renders client profiles whatever engine the servers run:
// sing-box profiles are what the apps import.
const ClientEngine = "sing-box"

// Engine renders the fleet into one engine's config format.
type Engine interface {
	Name() string
	// RenderServer renders the config of the named node.
	RenderServer(f *fleet.Fleet, node string) ([]byte, error)
	// RenderClient renders the profile the named user imports into their app.
	RenderClient(f *fleet.Fleet, user string) ([]byte, error)
	// RuleSets lists the files in RuleSetDir a rendered server config loads.
	RuleSets(config []byte) []string
}

var (
	registryMu sync.RWMutex
	registry   = map[string]func() Engine{}
)

// Register adds a factory under the engine's name. Safe to call from init().
func Register(name string, factory func() Engine) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// Lookup returns a fresh engine instance for the given name.
func Lookup(name string) (Engine, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown engine %q", name)
	}
	return f(), nil
}

func unregister(name string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, name)
}
