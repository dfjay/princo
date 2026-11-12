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
	"unicode/utf8"
)

// certWarning is how long before a certificate expires its check fails:
// ACME renews with a month left, so by then renewal has failed for weeks.
const certWarning = 14 * 24 * time.Hour

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
	// HTTP reaches Telegram.
	HTTP *http.Client
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

// Run checks the node and tells Telegram which checks changed state. A
// failed check is no error; failing to tell or keep the state is. With
// dryRun it only prints the results.
func (m *Monitor) Run(ctx context.Context, dryRun bool) error {
	results, skipped := m.check(ctx)
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
	now := m.Now()
	st.update(results, skipped, now)

	var errs []error
	for _, r := range m.reports(st) {
		if err := m.Config.Telegram.send(ctx, m.HTTP, r.text); err != nil {
			// The next run tells what still differs then.
			errs = append(errs, err)
			break
		}
		for _, c := range r.checks {
			c.Reported = c.Down
		}
	}
	if err := st.save(m.StatePath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type report struct {
	text   string
	checks []*checkState
}

// reports tells of the checks whose state Telegram hasn't heard, in as
// many messages as its limit takes.
func (m *Monitor) reports(st *state) []report {
	var out []report
	for _, id := range slices.Sorted(maps.Keys(st.Checks)) {
		c := st.Checks[id]
		if c.Down == c.Reported {
			continue
		}
		line := "\n" + describe(id, c)
		if n := len(out); n == 0 || utf8.RuneCountInString(out[n-1].text+line) > maxMessage {
			out = append(out, report{text: "princo node " + m.Config.Node})
		}
		r := &out[len(out)-1]
		r.text += line
		r.checks = append(r.checks, c)
	}
	return out
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
		r.ok = left >= certWarning
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

// describe is the line that tells Telegram of c's new state.
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
