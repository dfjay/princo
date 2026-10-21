// Package xray renders the princo resolved model into Xray-core JSON.
package xray

import (
	"bytes"
	"errors"

	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

func init() {
	engine.Register("xray", func() engine.Engine { return New() })
}

// MinVersion is the oldest Xray-core the rendered configs are tested with.
const MinVersion = "26.3.27"

// Engine is the xray renderer.
type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Name() string { return "xray" }

// RenderClient fails: users' apps get sing-box profiles and share links.
func (e *Engine) RenderClient(*fleet.Fleet, string) ([]byte, error) {
	return nil, errors.New("xray renders no client profiles")
}

// RuleSets lists the geodata files a rendered config loads.
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
