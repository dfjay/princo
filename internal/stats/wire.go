package stats

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// The protobuf wire format of the fields princo reads from
// ConnectionEvents, ConnectionEvent and Connection, in sing-box's
// daemon/started_service.proto. It skips the rest, destinations among them.

const (
	wireVarint = 0
	wire64     = 1
	wireBytes  = 2
	wire32     = 5
)

var errTruncated = errors.New("truncated message")

type field struct {
	num   int
	wire  int
	value uint64 // varint, fixed64, fixed32
	bytes []byte // bytes
}

// fields calls fn for each field of msg.
func fields(msg []byte, fn func(field) error) error {
	for len(msg) > 0 {
		tag, n := uvarint(msg)
		if n <= 0 {
			return errTruncated
		}
		msg = msg[n:]
		f := field{num: int(tag >> 3), wire: int(tag & 7)}
		switch f.wire {
		case wireVarint:
			if f.value, n = uvarint(msg); n <= 0 {
				return errTruncated
			}
			msg = msg[n:]
		case wire64:
			if len(msg) < 8 {
				return errTruncated
			}
			msg = msg[8:]
		case wire32:
			if len(msg) < 4 {
				return errTruncated
			}
			msg = msg[4:]
		case wireBytes:
			l, n := uvarint(msg)
			if n <= 0 || uint64(len(msg)-n) < l {
				return errTruncated
			}
			f.bytes, msg = msg[n:n+int(l)], msg[n+int(l):]
		default:
			return fmt.Errorf("wire type %d", f.wire)
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

// uvarint decodes a varint; n is 0 or less when msg holds none.
func uvarint(msg []byte) (v uint64, n int) {
	for i, b := range msg {
		if i == 10 {
			return 0, -1
		}
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendVarintField(b []byte, num int, v uint64) []byte {
	return appendVarint(appendVarint(b, uint64(num)<<3|wireVarint), v)
}

func decodeEvents(msg []byte) (Events, error) {
	var out Events
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireBytes:
			e, err := decodeEvent(f.bytes)
			if err != nil {
				return err
			}
			out.Events = append(out.Events, e)
		case f.num == 2 && f.wire == wireVarint:
			out.Reset = f.value != 0
		}
		return nil
	})
	return out, err
}

func decodeEvent(msg []byte) (Event, error) {
	var e Event
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireVarint:
			e.Type = EventType(f.value)
		case f.num == 2 && f.wire == wireBytes:
			e.ID = string(f.bytes)
		case f.num == 3 && f.wire == wireBytes:
			c, err := decodeConn(f.bytes)
			if err != nil {
				return err
			}
			e.Conn = c
		case f.num == 4 && f.wire == wireVarint:
			e.UploadDelta = int64(f.value)
		case f.num == 5 && f.wire == wireVarint:
			e.DownloadDelta = int64(f.value)
		case f.num == 6 && f.wire == wireVarint:
			e.ClosedAt = millis(f.value)
		}
		return nil
	})
	if e.Conn != nil && e.ID == "" {
		e.ID = e.Conn.ID
	}
	return e, err
}

func decodeConn(msg []byte) (*Conn, error) {
	c := &Conn{}
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireBytes:
			c.ID = string(f.bytes)
		case f.num == 6 && f.wire == wireBytes:
			c.Source = sourceAddr(string(f.bytes))
		case f.num == 10 && f.wire == wireBytes:
			c.User = string(f.bytes)
		case f.num == 12 && f.wire == wireVarint:
			c.Created = millis(f.value)
		case f.num == 13 && f.wire == wireVarint:
			c.Closed = millis(f.value)
		case f.num == 16 && f.wire == wireVarint:
			c.Upload = int64(f.value)
		case f.num == 17 && f.wire == wireVarint:
			c.Download = int64(f.value)
		}
		return nil
	})
	return c, err
}

// sourceAddr is the client's address from host:port, as one family.
func sourceAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

func millis(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(v))
}
