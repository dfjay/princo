package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootCommand_Version(t *testing.T) {
	var stdout bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"version"})

	require.NoError(t, cmd.Execute())
	require.Contains(t, stdout.String(), "princo")
}
