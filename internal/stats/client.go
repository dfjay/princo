// Package stats talks to sing-box's API service (fleet.API) over gRPC-Web.
// It reads the connections the engine tracks: their users, sources and
// traffic, skipping their destinations, which the API sends too. For the
// monitor it tests an outbound (control.go).
package stats

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Conn is one connection the engine tracks.
type Conn struct {
	ID string
	// User is empty when no account connected.
	User     string
	Source   netip.Addr
	Created  time.Time
	Closed   time.Time
	Upload   int64
	Download int64
}

// EventType is what happened to a connection.
type EventType int

// The types of daemon.ConnectionEventType.
const (
	New EventType = iota
	Update
	Closed
)

type Event struct {
	Type EventType
	ID   string
	// Conn is set on New, and on Closed when the engine still knew it.
	Conn *Conn
	// UploadDelta and DownloadDelta are an Update's traffic.
	UploadDelta, DownloadDelta int64
	ClosedAt                   time.Time
}

// Events is one message. The first has Reset set and brings the open
// connections and the last ones closed.
type Events struct {
	Reset  bool
	Events []Event
}

// Client reaches the API at URL, e.g. http://127.0.0.1:8446, through HTTP.
type Client struct {
	HTTP   *http.Client
	URL    string
	Secret string
}

var (
	ErrUnauthenticated = errors.New("the engine refused the API secret; deploy the node again")
	// ErrStop, from Subscribe's callback, ends it without an error.
	ErrStop = errors.New("stop")
)

// Subscribe calls fn with each message, every interval at most, until ctx
// ends, fn fails or the engine stops.
func (c *Client) Subscribe(ctx context.Context, interval time.Duration, fn func(Events) error) error {
	return c.call(ctx, "SubscribeConnections", appendVarintField(nil, 1, uint64(interval.Nanoseconds())), func(payload []byte) error {
		events, err := decodeEvents(payload)
		if err != nil {
			return fmt.Errorf("reading the engine's API: %w", err)
		}
		return fn(events)
	})
}

// call calls method of daemon.StartedService with msg and passes fn each
// message of the answer, until ctx ends, fn fails or returns ErrStop, or
// the engine ends the call.
func (c *Client) call(ctx context.Context, method string, msg []byte, fn func(payload []byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/daemon.StartedService/"+method, bytes.NewReader(frame(0, msg)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("reaching the engine's API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the engine's API answered %s; does the node run sing-box 1.14 or newer with its API on?", resp.Status)
	}
	// A call that fails at once answers with headers alone.
	if err := grpcStatus(resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")); err != nil {
		return err
	}
	r := bufio.NewReader(resp.Body)
	for {
		flag, payload, err := readFrame(r)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reading the engine's API: %w", err)
		}
		if flag&0x80 != 0 { // the trailers, with the call's status
			var code, message string
			for line := range strings.Lines(string(payload)) {
				k, v, _ := strings.Cut(strings.TrimSpace(line), ":")
				switch strings.ToLower(k) {
				case "grpc-status":
					code = strings.TrimSpace(v)
				case "grpc-message":
					message = strings.TrimSpace(v)
				}
			}
			if code == "" {
				return errors.New("the engine's API ended without a status")
			}
			return grpcStatus(code, message)
		}
		if err := fn(payload); err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}
			return err
		}
	}
}

func grpcStatus(code, message string) error {
	switch code {
	case "", "0":
		return nil
	case "16":
		return ErrUnauthenticated
	}
	// gRPC percent-encodes it.
	if m, err := url.PathUnescape(message); err == nil {
		message = m
	}
	return fmt.Errorf("the engine's API failed: gRPC status %s: %s", code, message)
}

// frame is a gRPC frame: a flag byte, the length, the message.
func frame(flag byte, msg []byte) []byte {
	out := make([]byte, 5, 5+len(msg))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:], uint32(len(msg)))
	return append(out, msg...)
}

// maxFrame bounds a message, which holds up to 1000 closed connections
// and every open one.
const maxFrame = 64 << 20

func readFrame(r io.Reader) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("a message of %d bytes", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return head[0], payload, nil
}
