// Package singbox renders the princo resolved model into sing-box JSON.
package singbox

import (
	"github.com/dfjay/princo/internal/engine"
	"github.com/dfjay/princo/internal/fleet"
)

const engineName = fleet.SingBox

func init() {
	engine.Register(engineName, func() engine.Engine { return New() })
}

// Engine is the sing-box renderer.
type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Name() string { return engineName }

func (e *Engine) MinVersion() string { return "1.14.0" }

// renderLog renders a fleet log level.
func renderLog(level string) map[string]any {
	if level == fleet.LogNone {
		return map[string]any{"disabled": true}
	}
	return map[string]any{"level": level, "timestamp": true}
}
