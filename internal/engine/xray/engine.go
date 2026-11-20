// Package xray renders the princo resolved model into Xray-core JSON.
package xray

import (
	"bytes"
	"errors"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

const engineName = fleet.Xray

func init() {
	engine.Register(engineName, func() engine.Engine { return New() })
}

// minVersion is the first release whose freedom resolves domains by
// sockopt.domainStrategy; it also blocks private addresses for VLESS users.
const minVersion = "26.9.8"

// Engine is the xray renderer.
type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Name() string { return engineName }

func (e *Engine) MinVersion() string { return minVersion }

// RenderClient fails: users' apps get sing-box profiles and share links.
func (e *Engine) RenderClient(*fleet.Fleet, string, engine.Platform, string) ([]byte, error) {
	return nil, errors.New("xray renders no client profiles")
}

func (e *Engine) ClientPlatforms() []engine.Platform { return nil }

// RuleSets lists the geodata files a rendered config loads.
// ClientRuleSets is empty: xray renders no client profiles.
func (e *Engine) ClientRuleSets([]byte) []string { return nil }

func (e *Engine) RuleSets(config []byte) []string {
	out := []string{}
	if bytes.Contains(config, []byte(`"geoip:`)) {
		out = append(out, "geoip.dat")
	}
	if bytes.Contains(config, []byte(`"geosite:`)) {
		out = append(out, "geosite.dat")
	}
	return out
}
