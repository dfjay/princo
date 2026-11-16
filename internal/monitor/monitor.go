package monitor

import (
	"cmp"
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
	// Followed by a certificate's name, a server name or a node's name.
	checkCert   = "certificate/"
	checkServed = "served/"
	checkReach  = "reach/"
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
		// failed is how many of routes didn't reach the channel.
		failed int
		err    error
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
			d.told, d.failed, d.err = m.send(ctx, d.channel, d.routes, d.changes)
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
	via := map[string]bool{}
	for _, ch := range m.Config.Notify {
		for _, node := range ch.Via {
			via[node] = true
		}
	}
	for _, d := range deliveries {
		for i, r := range d.routes {
			switch {
			case r.via == "" || i > d.failed:
			case i < d.failed:
				if st.ViaFailed == nil {
					st.ViaFailed = map[string]time.Time{}
				}
				st.ViaFailed[r.via] = m.Now()
			default:
				delete(st.ViaFailed, r.via)
			}
		}
	}
	maps.DeleteFunc(st.ViaFailed, func(node string, _ time.Time) bool { return !via[node] })
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

// routes lists the ways to try ch in turn: directly, or through its nodes.
// Those the latest run couldn't reach come last, and before them those a
// report failed to leave through, the latest failure last: a run that
// can't try them all tries others than the one before it.
func (m *Monitor) routes(ch Channel, st *state) []route {
	if len(ch.Via) == 0 {
		return []route{{client: m.HTTP}}
	}
	down := func(node string) int {
		if c := st.Checks[checkReach+node]; c != nil && c.Down != (c.Streak > 0) {
			return 1
		}
		return 0
	}
	via := slices.Clone(ch.Via)
	slices.SortStableFunc(via, func(a, b string) int {
		return cmp.Or(cmp.Compare(down(a), down(b)), st.ViaFailed[a].Compare(st.ViaFailed[b]))
	})
	var out []route
	for _, node := range via[:min(len(via), maxVia)] {
		out = append(out, route{node, m.Via(node)})
	}
	return out
}

// send tells ch of changes by the first of routes that reaches it, each
// with an equal share of the time left. It returns how many changes it
// told and how many routes didn't reach ch. A route goes on where the one
// before it stopped.
func (m *Monitor) send(ctx context.Context, ch Channel, routes []route, changes []change) (told, failed int, err error) {
	deadline, _ := ctx.Deadline()
	var errs []error
	for i, r := range routes {
		tryCtx, cancel := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(routes)-i))
		n, err := ch.sender().send(tryCtx, r.client, m.Config.Node, changes[told:])
		cancel()
		told += n
		if err == nil {
			return told, failed, nil
		}
		if r.via != "" {
			err = fmt.Errorf("through %s: %w", r.via, err)
		}
		errs = append(errs, err)
		if _, ok := errors.AsType[*unreachable](err); !ok {
			break
		}
		failed++
	}
	return told, failed, errors.Join(errs...)
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
	var wg sync.WaitGroup
	certs := make([][]result, len(c.Certificates))
	unasked := make([][]string, len(c.Certificates))
	for i, cert := range c.Certificates {
		wg.Go(func() { certs[i], unasked[i] = m.checkCert(ctx, cert, engine.ok) })
	}
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
	for _, id := range slices.Concat(unasked...) {
		skipped[id] = true
	}
	return slices.Concat(results, slices.Concat(certs...), warp, reach), skipped
}

func (m *Monitor) checkWarp(ctx context.Context) result {
	delay, err := m.Engine.TestOutbound(ctx, m.Config.Warp.Outbound)
	if err != nil {
		return result{id: checkWarp, detail: err.Error()}
	}
	return result{id: checkWarp, ok: true, detail: "answers in " + delay.String()}
}

// checkCert checks c's file and, with the certificate in it, each server
// that presents it. skipped are the servers it couldn't ask anything of.
func (m *Monitor) checkCert(ctx context.Context, c Certificate, engineRuns bool) (results []result, skipped []string) {
	file, cert := m.checkCertFile(c)
	// All at once: servers that hang would outlast the run one by one.
	var wg sync.WaitGroup
	served := make([]*result, len(c.Served))
	for i, s := range c.Served {
		id := checkServed + s.ServerName
		// Down with the engine, its servers have the engine's check.
		if cert == nil || s.Unit == m.Config.Unit && !engineRuns {
			skipped = append(skipped, id)
			continue
		}
		wg.Go(func() { served[i] = new(m.checkServed(ctx, id, s, c, cert)) })
	}
	wg.Wait()
	results = append(results, file)
	for _, r := range served {
		if r != nil {
			results = append(results, *r)
		}
	}
	return results, skipped
}

// checkCertFile checks that c's file holds a certificate with time left,
// and returns the certificate if it holds one.
func (m *Monitor) checkCertFile(c Certificate) (result, *x509.Certificate) {
	r := result{id: checkCert + c.Name}
	data, err := os.ReadFile(c.File)
	if err != nil {
		r.detail = "can't read it: " + err.Error()
		return r, nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		r.detail = c.File + " holds no PEM certificate"
		return r, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		r.detail = c.File + ": " + err.Error()
		return r, nil
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
	return r, cert
}

// checkServed checks that s presents cert, the one in c's file: a server
// that missed a renewal goes on with the old one until it expires.
func (m *Monitor) checkServed(ctx context.Context, id string, s Served, c Certificate, cert *x509.Certificate) result {
	r := result{id: id}
	presented, err := m.presented(ctx, s)
	switch {
	case err != nil:
		r.detail = "can't ask " + s.Unit + " at " + s.Address + ": " + reason(err)
	case !presented.Equal(cert):
		r.detail = fmt.Sprintf("%s presents one that expires on %s, not %s's in %s",
			s.Unit, presented.NotAfter.UTC().Format(time.DateOnly), c.Name, c.File)
	default:
		r.ok, r.detail = true, s.Unit+" presents "+c.Name+"'s"
	}
	return r
}

// presented is the certificate s presents.
func (m *Monitor) presented(ctx context.Context, s Served) (*x509.Certificate, error) {
	dialCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	conn, err := m.Dial(dialCtx, "tcp", s.Address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	// Which certificate, not whether it is valid: the file's has its check.
	client := tls.Client(conn, &tls.Config{ServerName: s.ServerName, InsecureSkipVerify: true}) //nolint:gosec
	hsCtx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	if err := client.HandshakeContext(hsCtx); err != nil {
		return nil, err
	}
	return client.ConnectionState().PeerCertificates[0], nil
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
	case strings.HasPrefix(id, checkServed) && c.Down:
		return "🔴 Certificate served as " + name + ": " + c.Detail
	case strings.HasPrefix(id, checkServed):
		return "🟢 Certificate served as " + name + " is the one on disk again" + after
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
