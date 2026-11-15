package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sendTimeout bounds what a channel takes to hear a run's changes.
const sendTimeout = 15 * time.Second

// stepTimeout bounds a connection attempt and a TLS handshake each.
const stepTimeout = 8 * time.Second

// Check IDs, as the state file keys them.
const (
	checkEngine = "engine"
	checkWarp   = "warp"
	// Followed by a certificate's or a node's name.
	checkCert  = "certificate/"
	checkReach = "reach/"
)

// Engine is the engine's API; see stats.Client.
type Engine interface {
	TestOutbound(ctx context.Context, tag string) (time.Duration, error)
}

// Monitor runs a node's checks.
type Monitor struct {
	Config    *Config
	StatePath string
	// Out gets each check's result, a line each.
	Out io.Writer
	Now func() time.Time
	// HTTP reaches the channels.
	HTTP *http.Client
	// Via reaches them through the node named, by Config.Proxy.
	Via  func(node string) *http.Client
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Active fails unless the systemd unit runs.
	Active func(ctx context.Context, unit string) error
	// Engine is needed where Config.Warp is set.
	Engine Engine
}

type result struct {
	id     string
	ok     bool
	detail string
}

// Run checks the node and tells each channel which checks changed state
// since it last heard. A failed check is no error; failing to tell or keep
// the state is. With dryRun it only prints the results.
func (m *Monitor) Run(ctx context.Context, dryRun bool) error {
	if !dryRun {
		unlock, err := lock(m.StatePath)
		if err != nil {
			return err
		}
		defer unlock()
	}
	results, skipped := m.check(ctx)
	if err := ctx.Err(); err != nil {
		// Cut short, the checks failed for no fault of the node's.
		return err
	}
	for _, r := range results {
		status := "ok  "
		if !r.ok {
			status = "FAIL"
		}
		line := status + " " + r.id
		if r.detail != "" {
			line += ": " + r.detail
		}
		if _, err := fmt.Fprintln(m.Out, line); err != nil {
			return err
		}
	}
	if dryRun {
		return nil
	}
	st, err := loadState(m.StatePath)
	if err != nil {
		return err
	}
	st.update(results, skipped, m.Config.Confirm, m.Now())
	errs := m.notify(ctx, st)
	if err := st.save(m.StatePath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// notify tells each channel of the checks whose state it hasn't heard, all
// at once and each with its own time: one that hangs keeps nothing from
// the others. What a channel couldn't be told, the next run tells.
func (m *Monitor) notify(ctx context.Context, st *state) []error {
	type delivery struct {
		channel Channel
		id      string
		changes []change
		checks  []*checkState
		routes  []route
		told    int
		err     error
	}
	var deliveries []*delivery
	ids := map[string]bool{}
	for _, ch := range m.Config.Notify {
		d := &delivery{channel: ch, id: ch.id()}
		ids[d.id] = true
		for _, name := range slices.Sorted(maps.Keys(st.Checks)) {
			if c := st.Checks[name]; c.Down != c.Told[d.id] {
				d.changes = append(d.changes, change{Check: name, Down: c.Down, Detail: c.Detail, Text: describe(name, c)})
				d.checks = append(d.checks, c)
			}
		}
		if len(d.changes) > 0 {
			d.routes = m.routes(ch, st)
			deliveries = append(deliveries, d)
		}
	}
	var wg sync.WaitGroup
	for _, d := range deliveries {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, sendTimeout)
			defer cancel()
			d.told, d.err = m.send(ctx, d.channel, d.routes, d.changes)
		})
	}
	wg.Wait()
	var errs []error
	for _, d := range deliveries {
		if d.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.channel.Name, d.err))
		}
		for _, c := range d.checks[:d.told] {
			c.tell(d.id)
		}
	}
	// A channel that is gone, or leads elsewhere now, is forgotten.
	for _, c := range st.Checks {
		maps.DeleteFunc(c.Told, func(id string, _ bool) bool { return !ids[id] })
	}
	return errs
}

// maxVia is how many nodes a run tries a channel through, each with its
// share of sendTimeout.
const maxVia = 3

// route is a way to a channel: through the node via, or directly.
type route struct {
	via    string
	client *http.Client
}

// routes lists the ways to try ch in turn: directly, or through its nodes,
// those the latest run reached first.
func (m *Monitor) routes(ch Channel, st *state) []route {
	if len(ch.Via) == 0 {
		return []route{{client: m.HTTP}}
	}
	var up, down []string
	for _, node := range ch.Via {
		if c := st.Checks[checkReach+node]; c != nil && c.Down != (c.Streak > 0) {
			down = append(down, node)
		} else {
			up = append(up, node)
		}
	}
	var out []route
	for _, node := range append(up, down...)[:min(len(ch.Via), maxVia)] {
		out = append(out, route{node, m.Via(node)})
	}
	return out
}

// send tells ch of changes by the first of routes that reaches it, each
// with an equal share of the time left, and returns how many it told. A
// route goes on where the one before it stopped.
func (m *Monitor) send(ctx context.Context, ch Channel, routes []route, changes []change) (int, error) {
	deadline, _ := ctx.Deadline()
	told := 0
	var errs []error
	for i, r := range routes {
		tryCtx, cancel := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(routes)-i))
		n, err := ch.sender().send(tryCtx, r.client, m.Config.Node, changes[told:])
		cancel()
		told += n
		if err == nil {
			return told, nil
		}
		if r.via != "" {
			err = fmt.Errorf("through %s: %w", r.via, err)
		}
		errs = append(errs, err)
		if _, ok := errors.AsType[*unreachable](err); !ok {
			break
		}
	}
	return told, errors.Join(errs...)
}

// check runs every check. skipped are those it couldn't tell about, whose
// states stay.
func (m *Monitor) check(ctx context.Context) (results []result, skipped map[string]bool) {
	c := m.Config
	skipped = map[string]bool{}
	engine := result{id: checkEngine, ok: true}
	if err := m.Active(ctx, c.Unit); err != nil {
		engine.ok, engine.detail = false, c.Unit+" isn't running"
	}
	results = append(results, engine)
	for _, cert := range c.Certificates {
		results = append(results, m.checkCert(cert))
	}
	var wg sync.WaitGroup
	var warp []result
	switch {
	case c.Warp == nil:
	case !engine.ok:
		// It is down with the engine, which has its own check.
		skipped[checkWarp] = true
	default:
		warp = make([]result, 1)
		wg.Go(func() { warp[0] = m.checkWarp(ctx) })
	}
	reach := make([]result, len(c.Reach))
	for i, t := range c.Reach {
		wg.Go(func() { reach[i] = m.checkReach(ctx, t) })
	}
	wg.Wait()
	return slices.Concat(results, warp, reach), skipped
}

func (m *Monitor) checkWarp(ctx context.Context) result {
	delay, err := m.Engine.TestOutbound(ctx, m.Config.Warp.Outbound)
	if err != nil {
		return result{id: checkWarp, detail: err.Error()}
	}
	return result{id: checkWarp, ok: true, detail: "answers in " + delay.String()}
}

func (m *Monitor) checkCert(c Certificate) result {
	r := result{id: checkCert + c.Name}
	data, err := os.ReadFile(c.File)
	if err != nil {
		r.detail = "can't read it: " + err.Error()
		return r
	}
	block, _ := pem.Decode(data)
	if block == nil {
		r.detail = c.File + " holds no PEM certificate"
		return r
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		r.detail = c.File + ": " + err.Error()
		return r
	}
	left := cert.NotAfter.Sub(m.Now())
	day := cert.NotAfter.UTC().Format(time.DateOnly)
	switch {
	case left <= 0:
		r.detail = "expired on " + day
	default:
		r.ok = left >= time.Duration(m.Config.CertificateDays)*24*time.Hour
		r.detail = fmt.Sprintf("expires in %d days, on %s", int(left.Hours()/24), day)
	}
	return r
}

// checkReach connects to t as a client would begin to: an address blocked
// on the way refuses the connection, a name blocked there the handshake.
func (m *Monitor) checkReach(ctx context.Context, t Target) result {
	r := result{id: checkReach + t.Node}
	addr := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
	dialCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	conn, err := m.Dial(dialCtx, "tcp", addr)
	if err != nil {
		r.detail = "connecting to " + addr + ": " + reason(err)
		return r
	}
	defer func() { _ = conn.Close() }()
	if t.ServerName != "" {
		// Reachability only: whose certificate answers isn't the question.
		client := tls.Client(conn, &tls.Config{ServerName: t.ServerName, InsecureSkipVerify: true}) //nolint:gosec
		hsCtx, cancel := context.WithTimeout(ctx, stepTimeout)
		defer cancel()
		if err := client.HandshakeContext(hsCtx); err != nil {
			r.detail = "TLS handshake with " + addr + " as " + t.ServerName + ": " + reason(err)
			return r
		}
	}
	r.ok = true
	return r
}

// reason is err without the addresses net errors repeat.
func reason(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

// describe tells of c's new state in a line.
func describe(id string, c *checkState) string {
	after := ", after " + span(time.Duration(c.LastedSeconds)*time.Second)
	name := id[strings.IndexByte(id, '/')+1:]
	switch {
	case id == checkEngine && c.Down:
		return "🔴 The engine is down: " + c.Detail
	case id == checkEngine:
		return "🟢 The engine runs again" + after
	case id == checkWarp && c.Down:
		return "🔴 WARP is down: " + c.Detail + ". Traffic through the node stalls."
	case id == checkWarp:
		return "🟢 WARP works again" + after
	case strings.HasPrefix(id, checkCert) && c.Down:
		return "🔴 Certificate " + name + ": " + c.Detail
	case strings.HasPrefix(id, checkCert):
		return "🟢 Certificate " + name + " is fine again: " + c.Detail
	case c.Down:
		return "🔴 Can't reach node " + name + ": " + c.Detail
	default:
		return "🟢 Node " + name + " is reachable again" + after
	}
}

// span formats d to two units, e.g. 12m, 2h13m or 3d4h.
func span(d time.Duration) string {
	d = d.Round(time.Minute)
	days, hours, minutes := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh%dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm", minutes)
	default:
		return "less than a minute"
	}
}
