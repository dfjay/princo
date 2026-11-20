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
	// RuleSetSitePath is where the subscription site serves the client
	// profiles' rule sets from RuleSetDir, so they match the nodes',
	// unless they are published elsewhere (fleet.Subscription.RuleSetURL).
	RuleSetSitePath = fleet.RuleSetSitePath
	// CertDir holds <certificate name>/{fullchain,key}.pem.
	CertDir        = "/var/lib/princo/certs"
	MuxRealityPort = fleet.MuxRealityPort
	MuxNaivePort   = fleet.MuxNaivePort
	// LoopbackInterface binds the engine's listeners behind the
	// multiplexer, on :: for both 127.0.0.1 and ::1.
	LoopbackInterface = "lo"
	APIPort           = fleet.APIPort
	MonitorPort       = fleet.MonitorPort
)

// WarpTag is the WARP outbound, or endpoint, of a server config, which the
// monitor names to the engine's API.
const WarpTag = "warp"

// MonitorInbound is the SOCKS proxy of a server config that the monitor
// sends its reports through; its user names the node they leave by.
const MonitorInbound = "monitor-in"

// MonitorTag is the outbound those reports leave through up with; no
// node's name has a colon to make another outbound's tag of it.
func MonitorTag(up *fleet.Node) string { return "monitor:" + up.Name }

// MonitorAccounts names the nodes that send their reports through n, as
// they log in there.
func MonitorAccounts(f *fleet.Fleet, n *fleet.Node) []any {
	var out []any
	for _, m := range f.MonitorsInto(n) {
		out = append(out, fleet.MonitorAccount(m))
	}
	return out
}

// WarpPeerPublicKey is Cloudflare WARP's WireGuard peer key.
const WarpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

// ClientEngine renders client profiles whatever engine the servers run.
const ClientEngine = fleet.ClientEngine

// Platform is what a client profile runs on.
type Platform string

const (
	// AnyPlatform is a profile for the apps, whatever they run on.
	AnyPlatform Platform = ""
	// Linux is a profile for sing-box or another engine running as a
	// Linux service, a router's included.
	Linux Platform = "linux"
)

// Engine renders the fleet into one engine's config format.
type Engine interface {
	Name() string
	// MinVersion is the oldest release of the engine its configs work on.
	MinVersion() string
	// RenderServer renders the config of the named node.
	RenderServer(f *fleet.Fleet, node string) ([]byte, error)
	// RenderClient renders the named user's profile for platform p, as the
	// subscription site serves it under domain; empty without the site.
	RenderClient(f *fleet.Fleet, user string, p Platform, domain string) ([]byte, error)
	// ClientPlatforms are the platforms besides AnyPlatform it renders
	// profiles for.
	ClientPlatforms() []Platform
	// RuleSets lists the files in RuleSetDir a rendered server config loads.
	RuleSets(config []byte) []string
	// ClientRuleSets lists the files a rendered client profile fetches
	// from its rule sets' origin (fleet.RuleSetOrigin).
	ClientRuleSets(profile []byte) []string
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
