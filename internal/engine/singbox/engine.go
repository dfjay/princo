// Package singbox renders the princo resolved model into sing-box JSON.
package singbox

import "github.com/dfjay/princo/internal/engine"

func init() {
	engine.Register("sing-box", func() engine.Engine { return New() })
}

// Engine is the sing-box renderer.
type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Name() string { return "sing-box" }

func (e *Engine) MinVersion() string { return "1.14.0" }
