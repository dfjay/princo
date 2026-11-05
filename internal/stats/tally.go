package stats

import (
	"cmp"
	"net/netip"
	"slices"
	"time"
)

// Tally follows a node's connections from its events. By default it
// counts what the engine remembers at the start: the open connections and
// the last 1000 closed. With Window it counts only what happens after the
// start: connections open then or opened since, and their traffic since.
type Tally struct {
	Window bool
	// User, when set, is the only user it counts.
	User string

	start time.Time
	conns map[string]*tracked
	// done folds the connections closed in the window, by user, so a long
	// window keeps no record of each.
	done map[string]*folded
}

type tracked struct {
	Conn
	// The traffic before the window.
	baseUp, baseDown int64
}

type folded struct {
	conns            int
	ips              map[netip.Addr]int
	upload, download int64
}

// Add applies one message, which came at now.
func (t *Tally) Add(e Events, now time.Time) {
	if t.conns == nil || e.Reset {
		t.conns = map[string]*tracked{}
	}
	first := t.start.IsZero()
	if first {
		t.start = now
	}
	for _, ev := range e.Events {
		c := t.conns[ev.ID]
		switch ev.Type {
		case New:
			if ev.Conn == nil {
				continue
			}
			if t.Window && first && !ev.Conn.Closed.IsZero() {
				continue // closed before the window
			}
			if t.User != "" && ev.Conn.User != t.User {
				continue
			}
			c = &tracked{Conn: *ev.Conn}
			if t.Window && first {
				c.baseUp, c.baseDown = c.Upload, c.Download
			}
			t.conns[ev.ID] = c
		case Update:
			if c != nil {
				c.Upload += ev.UploadDelta
				c.Download += ev.DownloadDelta
			}
		case Closed:
			if c == nil {
				continue
			}
			if ev.Conn != nil {
				c.Upload, c.Download = ev.Conn.Upload, ev.Conn.Download
			}
			c.Closed = cmp.Or(ev.ClosedAt, now)
			if t.Window {
				t.fold(c)
				delete(t.conns, ev.ID)
			}
		}
	}
}

func (t *Tally) fold(c *tracked) {
	if t.done == nil {
		t.done = map[string]*folded{}
	}
	f := t.done[c.User]
	if f == nil {
		f = &folded{ips: map[netip.Addr]int{}}
		t.done[c.User] = f
	}
	f.conns++
	f.upload += c.Upload - c.baseUp
	f.download += c.Download - c.baseDown
	if c.Source.IsValid() {
		f.ips[c.Source]++
	}
}

// Settle takes the totals of the connections still open from e, a later
// first message, for their traffic since the last update, and folds
// those it shows closed.
func (t *Tally) Settle(e Events) {
	for _, ev := range e.Events {
		c := t.conns[ev.ID]
		if c == nil || ev.Conn == nil || !c.Closed.IsZero() {
			continue
		}
		c.Upload, c.Download = ev.Conn.Upload, ev.Conn.Download
		if c.Closed = ev.Conn.Closed; !c.Closed.IsZero() && t.Window {
			t.fold(c)
			delete(t.conns, ev.ID)
		}
	}
}

type Report struct {
	// Rows are by traffic, the most first, then by user.
	Rows         []Row
	Open, Closed int
	// Since is when the window started, or else when the oldest
	// connection opened.
	Since time.Time
}

type Row struct {
	User       string
	Open, Conn int
	// IPs are by connections, the most first.
	IPs              []IP
	Upload, Download int64
}

type IP struct {
	Addr  netip.Addr
	Conns int
}

// Report tallies the connections by user.
func (t *Tally) Report() Report {
	var r Report
	if t.Window {
		r.Since = t.start
	}
	rows := map[string]*Row{}
	ips := map[string]map[netip.Addr]int{}
	rowOf := func(user string) *Row {
		if rows[user] == nil {
			rows[user] = &Row{User: user}
			ips[user] = map[netip.Addr]int{}
		}
		return rows[user]
	}
	for user, f := range t.done {
		row := rowOf(user)
		row.Conn += f.conns
		r.Closed += f.conns
		row.Upload += f.upload
		row.Download += f.download
		for addr, n := range f.ips {
			ips[user][addr] += n
		}
	}
	for _, c := range t.conns {
		row := rowOf(c.User)
		row.Conn++
		if c.Closed.IsZero() {
			row.Open++
			r.Open++
		} else {
			r.Closed++
		}
		row.Upload += c.Upload - c.baseUp
		row.Download += c.Download - c.baseDown
		if c.Source.IsValid() {
			ips[c.User][c.Source]++
		}
		if !t.Window && !c.Created.IsZero() && (r.Since.IsZero() || c.Created.Before(r.Since)) {
			r.Since = c.Created
		}
	}
	for user, row := range rows {
		for addr, n := range ips[user] {
			row.IPs = append(row.IPs, IP{Addr: addr, Conns: n})
		}
		slices.SortFunc(row.IPs, func(a, b IP) int {
			return cmp.Or(cmp.Compare(b.Conns, a.Conns), a.Addr.Compare(b.Addr))
		})
		r.Rows = append(r.Rows, *row)
	}
	slices.SortFunc(r.Rows, func(a, b Row) int {
		return cmp.Or(cmp.Compare(b.Upload+b.Download, a.Upload+a.Download), cmp.Compare(a.User, b.User))
	})
	return r
}
