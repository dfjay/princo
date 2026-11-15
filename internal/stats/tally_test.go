package stats

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dfjay/princo/internal/engineapi"
)

var t0 = time.UnixMilli(1_790_000_000_000)

func TestTally(t *testing.T) {
	open := engineapi.Conn{ID: "1", User: "alice", Created: t0, Upload: 100, Download: 1000}
	closed := engineapi.Conn{ID: "2", User: "alice", Created: t0.Add(-time.Hour), Closed: t0, Upload: 5, Download: 50}
	other := engineapi.Conn{ID: "3", User: "bob", Created: t0, Upload: 1, Download: 1}
	start := engineapi.Events{Reset: true, Events: []engineapi.Event{
		{Type: engineapi.New, ID: "1", Conn: withSource(open, "198.51.100.1")},
		{Type: engineapi.New, ID: "2", Conn: withSource(closed, "198.51.100.2")},
		{Type: engineapi.New, ID: "3", Conn: withSource(other, "198.51.100.1")},
	}}
	later := engineapi.Events{Events: []engineapi.Event{
		{Type: engineapi.Update, ID: "1", UploadDelta: 10, DownloadDelta: 20},
		{Type: engineapi.New, ID: "4", Conn: withSource(engineapi.Conn{ID: "4", User: "alice", Created: t0.Add(time.Minute)}, "198.51.100.1")},
		{Type: engineapi.Update, ID: "4", UploadDelta: 3, DownloadDelta: 4},
		{Type: engineapi.Closed, ID: "3", Conn: withSource(engineapi.Conn{ID: "3", User: "bob", Upload: 2, Download: 9}, "198.51.100.1"), ClosedAt: t0.Add(2 * time.Minute)},
	}}

	// What the engine remembers at the start.
	var snap Tally
	snap.Add(start, t0)
	r := snap.Report()
	require.Equal(t, 2, r.Open)
	require.Equal(t, 1, r.Closed)
	require.Equal(t, t0.Add(-time.Hour), r.Since, "the oldest connection it remembers")
	require.Equal(t, []Row{
		{User: "alice", Open: 1, Conn: 2, Upload: 105, Download: 1050, IPs: []IP{
			{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 1}, {Addr: netip.MustParseAddr("198.51.100.2"), Conns: 1},
		}},
		{User: "bob", Open: 1, Conn: 1, Upload: 1, Download: 1, IPs: []IP{{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 1}}},
	}, r.Rows)

	// What happens over a window: no connection closed before it, no
	// traffic from before it.
	w := Tally{Window: true}
	w.Add(start, t0)
	w.Add(later, t0.Add(3*time.Minute))
	r = w.Report()
	require.Equal(t, t0, r.Since)
	require.Equal(t, 2, r.Open)
	require.Equal(t, 1, r.Closed)
	require.Equal(t, []Row{
		{User: "alice", Open: 2, Conn: 2, Upload: 13, Download: 24, IPs: []IP{{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 2}}},
		{User: "bob", Conn: 1, Upload: 1, Download: 8, IPs: []IP{{Addr: netip.MustParseAddr("198.51.100.1"), Conns: 1}}},
	}, r.Rows)
	require.Len(t, w.conns, 2, "the closed connection is folded, not kept")

	// The traffic since the last update, from the totals at the end.
	w.Settle(engineapi.Events{Reset: true, Events: []engineapi.Event{
		{Type: engineapi.New, ID: "1", Conn: withSource(engineapi.Conn{ID: "1", User: "alice", Upload: 200, Download: 2000}, "198.51.100.1")},
	}})
	require.Equal(t, int64(103), w.Report().Rows[0].Upload)
	w.Settle(engineapi.Events{Reset: true, Events: []engineapi.Event{
		{Type: engineapi.New, ID: "4", Conn: withSource(engineapi.Conn{ID: "4", User: "alice", Closed: t0.Add(4 * time.Minute), Upload: 3, Download: 4}, "198.51.100.1")},
	}})
	r = w.Report()
	require.Equal(t, 1, r.Open, "a close the window missed")
	require.Equal(t, 2, r.Closed)

	// One user's: the counts are theirs alone.
	only := Tally{User: "bob"}
	only.Add(start, t0)
	r = only.Report()
	require.Equal(t, 1, r.Open)
	require.Zero(t, r.Closed)
	require.Equal(t, t0, r.Since)
	require.Len(t, r.Rows, 1)
}

func withSource(c engineapi.Conn, addr string) *engineapi.Conn {
	c.Source = netip.MustParseAddr(addr)
	return &c
}
