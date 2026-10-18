// Package engine defines the contract every supported VPN engine (sing-box,
// xray, ...) implements, plus a registry for looking them up by name.
package engine

import (
	"fmt"
	"sync"

	"github.com/dfjay/princo/internal/fleet"
)

// Engine renders the fleet into one engine's config format.
type Engine interface {
	Name() string
	// RenderServer renders the config of the named node.
	RenderServer(f *fleet.Fleet, node string) ([]byte, error)
	// RenderClient renders the profile the named user imports into their app.
	RenderClient(f *fleet.Fleet, user string) ([]byte, error)
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
