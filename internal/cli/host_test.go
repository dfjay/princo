package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostApply_RefusesBeforeTouchingTheHost(t *testing.T) {
	for in, want := range map[string]string{
		`{"format": 0, "node": "de"}`: "bundle format 0, but this princo applies format 1",
		`not json`:                    "read bundle:",
	} {
		cmd := NewRootCommand()
		cmd.SetIn(strings.NewReader(in))
		cmd.SetArgs([]string{"host", "apply"})
		require.ErrorContains(t, cmd.Execute(), want)
	}
}
