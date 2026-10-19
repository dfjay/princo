package version

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestString(t *testing.T) {
	require.Regexp(t, regexp.MustCompile(`^\d+\.\d+\.\d+$`), number[:len(number)-1], "VERSION holds a bare semver line")

	Revision = "abc1234"
	t.Cleanup(func() { Revision = "" })
	require.Equal(t, number[:len(number)-1]+"+abc1234", String())
}
