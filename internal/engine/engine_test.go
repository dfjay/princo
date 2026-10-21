package engine

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/fleet"
)

func TestRegistry_LookupKnownEngine(t *testing.T) {
	dummy := &dummyEngine{name: "test-engine"}
	Register("test-engine", func() Engine { return dummy })
	t.Cleanup(func() { unregister("test-engine") })

	got, err := Lookup("test-engine")
	require.NoError(t, err)
	require.Same(t, dummy, got)
}

func TestRegistry_LookupUnknown(t *testing.T) {
	_, err := Lookup("does-not-exist")
	require.ErrorContains(t, err, "does-not-exist")
}

type dummyEngine struct{ name string }

func (d *dummyEngine) Name() string                                      { return d.name }
func (d *dummyEngine) RenderServer(*fleet.Fleet, string) ([]byte, error) { return nil, nil }
func (d *dummyEngine) RenderClient(*fleet.Fleet, string) ([]byte, error) { return nil, nil }
func (d *dummyEngine) RuleSets([]byte) []string                          { return nil }
