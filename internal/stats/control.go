package stats

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// testTimeout outlasts the engine's own limit on a test, 15 seconds.
const testTimeout = 20 * time.Second

// ErrTestFailed tells that the outbound passed no traffic.
var ErrTestFailed = errors.New("the test request got no answer")

// outboundTest is when the engine last tested an outbound successfully,
// in Unix seconds, and how long the answer took; zero when its last test
// failed or it had none.
type outboundTest struct {
	at    int64
	delay time.Duration
}

// TestOutbound has the engine request its test URL through the outbound or
// endpoint tag, and returns how long the answer took. It is ErrTestFailed
// when none came.
func (c *Client) TestOutbound(ctx context.Context, tag string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()
	var before outboundTest
	known := false
	err := c.outbounds(ctx, func(tests map[string]outboundTest) error {
		before, known = tests[tag]
		return ErrStop
	})
	if err != nil {
		return 0, err
	}
	if !known {
		return 0, fmt.Errorf("the engine has no outbound %s; deploy the node again", tag)
	}
	if err := c.call(ctx, "URLTest", appendBytesField(nil, 1, []byte(tag)), func([]byte) error { return nil }); err != nil {
		return 0, err
	}
	// The engine tests in the background and sends the list again when the
	// result is in: a new time, or none where the test failed.
	var after outboundTest
	done := false
	err = c.outbounds(ctx, func(tests map[string]outboundTest) error {
		after = tests[tag]
		if after == before {
			return nil
		}
		done = true
		return ErrStop
	})
	switch {
	case err != nil:
		return 0, err
	case !done && ctx.Err() == nil:
		return 0, errors.New("the engine's API ended the call before the test did")
	case !done, after.at == 0:
		// Without a result in time, what the engine has is the test before
		// this one: an answer then is none now.
		return 0, ErrTestFailed
	}
	return after.delay, nil
}

// outbounds passes fn the last test of every outbound and endpoint, by
// tag, now and whenever a test ends.
func (c *Client) outbounds(ctx context.Context, fn func(map[string]outboundTest) error) error {
	return c.call(ctx, "SubscribeOutbounds", nil, func(payload []byte) error {
		tests := map[string]outboundTest{}
		// OutboundList: repeated GroupItem outbounds = 1.
		err := fields(payload, func(f field) error {
			if f.num != 1 || f.wire != wireBytes {
				return nil
			}
			var tag string
			var t outboundTest
			// GroupItem: tag = 1, urlTestTime = 3, urlTestDelay = 4.
			err := fields(f.bytes, func(f field) error {
				switch {
				case f.num == 1 && f.wire == wireBytes:
					tag = string(f.bytes)
				case f.num == 3 && f.wire == wireVarint:
					t.at = int64(f.value)
				case f.num == 4 && f.wire == wireVarint:
					t.delay = time.Duration(int32(f.value)) * time.Millisecond
				}
				return nil
			})
			tests[tag] = t
			return err
		})
		if err != nil {
			return fmt.Errorf("reading the engine's API: %w", err)
		}
		return fn(tests)
	})
}
