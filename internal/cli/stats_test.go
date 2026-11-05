package cli

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/fleet/fleettest"
	"github.com/dfjay/princo/internal/stats"
)

func TestStatsNodes(t *testing.T) {
	f := fleettest.Load(t, "../../testdata/fleet")
	nodes, err := statsNodes(f, "")
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.Equal(t, "de", nodes[0].Name)
	_, err = statsNodes(f, "us")
	require.ErrorContains(t, err, "node us doesn't report its connections; set stats: true on it")
	_, err = statsNodes(f, "nope")
	require.ErrorContains(t, err, `no node named "nope"`)
}

func TestPrintStats(t *testing.T) {
	ip := func(s string, n int) stats.IP { return stats.IP{Addr: netip.MustParseAddr(s), Conns: n} }
	r := stats.Report{
		Open: 3, Closed: 40, Since: time.Date(2026, 11, 5, 14, 2, 0, 0, time.Local),
		Rows: []stats.Row{
			{User: "alice", Open: 2, Conn: 30, IPs: []stats.IP{ip("198.51.100.1", 20), ip("2001:db8::1", 10)}, Upload: 1536, Download: 3 << 30},
			{User: "", Open: 1, Conn: 13, Upload: 10},
		},
	}
	var out strings.Builder
	require.NoError(t, printStats(&out, "de", r, 0, "", true))
	require.Equal(t, `node de: 3 connections open, and the last 40 closed, the oldest from 2026-11-05 14:02:00
USER            OPEN  CONNECTIONS  ADDRESSES  UPLOAD   DOWNLOAD
alice           2     30           2          1.5 KiB  3.0 GiB
  198.51.100.1        20
  2001:db8::1         10
(none)          1     13           0          10 B     0 B
`, out.String())

	out.Reset()
	require.NoError(t, printStats(&out, "de", r, 10*time.Minute, "bob", false))
	require.Equal(t, "node de, 10m0s from 2026-11-05 14:02:00: 43 connections open or opened\nUSER  OPEN  CONNECTIONS  ADDRESSES  UPLOAD  DOWNLOAD\nno connections of bob\n", out.String())
}

func TestByteSize(t *testing.T) {
	require.Equal(t, "0 B", byteSize(0))
	require.Equal(t, "1023 B", byteSize(1023))
	require.Equal(t, "1.0 KiB", byteSize(1024))
	require.Equal(t, "1.0 MiB", byteSize(1<<20))
	require.Equal(t, "2.5 TiB", byteSize(5<<39))
}
