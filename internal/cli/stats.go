package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/deploy"
	"github.com/dfjay/princo/internal/fleet"
	"github.com/dfjay/princo/internal/stats"
)

func newStatsCommand(global *globalFlags) *cobra.Command {
	var nodeName, target, user string
	var window time.Duration
	var showIPs bool
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show who uses a node: connections, addresses and traffic by user",
		Long: `Show who uses a node: each user's connections, the addresses they
come from and their traffic, never where they go. The node needs stats: true
(sing-box only); princo stats reaches its engine over ssh -W, without root.

By default it counts the connections open now and the last 1000 closed.
With --for it watches the node that long and counts only what happens then.`,
		Example: `  princo stats --node fr
  princo stats --node fr --user alice --ips
  princo stats --node fr --for 1h`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if target != "" && nodeName == "" {
				return errors.New("--host needs --node")
			}
			if window < 0 {
				return errors.New("--for must not be negative")
			}
			ctx, stop := interruptible(cmd.Context())
			defer stop()
			f, err := loadFleet(global)
			if err != nil {
				return err
			}
			nodes, err := statsNodes(f, nodeName)
			if err != nil {
				return err
			}
			for i, n := range nodes {
				if i > 0 {
					if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
						return err
					}
				}
				r, err := nodeStats(ctx, cmd.ErrOrStderr(), n, target, window, user)
				if err != nil {
					return fmt.Errorf("node %s: %w", n.Name, err)
				}
				if err := printStats(cmd.OutOrStdout(), n.Name, r, window, user, showIPs); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "Node to ask (default: every node with stats: true)")
	cmd.Flags().StringVar(&target, "host", "", "SSH target, user@host (default: the node's ssh: in princo.yaml)")
	cmd.Flags().StringVar(&user, "user", "", "Show only this user")
	cmd.Flags().DurationVar(&window, "for", 0, "Watch the node this long, e.g. 10m, and count what happens meanwhile")
	cmd.Flags().BoolVar(&showIPs, "ips", false, "List each user's addresses")
	return cmd
}

// statsNodes are the nodes to ask: name, or every one with stats.
func statsNodes(f *fleet.Fleet, name string) ([]*fleet.Node, error) {
	if name != "" {
		n, ok := f.Node(name)
		if !ok {
			return nil, fmt.Errorf("no node named %q", name)
		}
		if n.Stats == nil {
			return nil, fmt.Errorf("node %s doesn't report its connections; set stats: true on it in princo.yaml, then princo secret gen and deploy it", name)
		}
		return []*fleet.Node{n}, nil
	}
	var out []*fleet.Node
	for _, n := range f.Nodes {
		if n.Stats != nil {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no node reports its connections; set stats: true on one in princo.yaml, then princo secret gen and deploy it")
	}
	return out, nil
}

// nodeStats asks n's engine over SSH, at once or for window, about user
// or, if empty, everyone.
func nodeStats(ctx context.Context, log io.Writer, n *fleet.Node, target string, window time.Duration, user string) (stats.Report, error) {
	if target == "" {
		if target = n.SSH; target == "" {
			return stats.Report{}, errors.New("no ssh: in princo.yaml; pass --host")
		}
	}
	ssh := &deploy.SSH{Target: target, Stderr: log}
	if err := ssh.Open(ctx); err != nil {
		return stats.Report{}, err
	}
	defer func() { _ = ssh.Close() }()
	api := net.JoinHostPort("127.0.0.1", strconv.Itoa(fleet.StatsPort))
	client := &stats.Client{
		HTTP: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return ssh.Dial(ctx, api) },
		}},
		URL:    "http://" + api,
		Secret: n.Stats.Secret,
	}
	// first passes fn the engine's first message: what it has now.
	first := func(fn func(stats.Events)) error {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		got := false
		err := client.Subscribe(ctx, time.Second, func(e stats.Events) error { fn(e); got = true; return stats.ErrStop })
		if err == nil && !got {
			err = errors.New("the engine's stats sent nothing")
		}
		return err
	}
	t := &stats.Tally{Window: window > 0, User: user}
	if window == 0 {
		err := first(func(e stats.Events) { t.Add(e, time.Now()) })
		return t.Report(), err
	}

	_, _ = fmt.Fprintf(log, "watching node %s for %s\n", n.Name, window) // progress only
	watch, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	err := client.Subscribe(watch, time.Second, func(e stats.Events) error {
		t.Add(e, time.Now())
		return nil
	})
	if err == nil {
		// Interrupted, it reports nothing rather than part of the window.
		err = ctx.Err()
	}
	if err == nil {
		// Open connections report traffic each second; their totals now
		// count what came since.
		err = first(t.Settle)
	}
	return t.Report(), err
}

func printStats(out io.Writer, node string, r stats.Report, window time.Duration, user string, showIPs bool) error {
	var b strings.Builder
	// Neither a strings.Builder nor a tabwriter onto one fails.
	printf := func(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	if window > 0 {
		printf(&b, "node %s, %s from %s: %d connections open or opened\n",
			node, window, r.Since.Local().Format(time.DateTime), r.Open+r.Closed)
	} else {
		printf(&b, "node %s: %d connections open, and the last %d closed", node, r.Open, r.Closed)
		if !r.Since.IsZero() {
			printf(&b, ", the oldest from %s", r.Since.Local().Format(time.DateTime))
		}
		printf(&b, "\n")
	}
	var table strings.Builder
	w := tabwriter.NewWriter(&table, 0, 4, 2, ' ', 0)
	printf(w, "USER\tOPEN\tCONNECTIONS\tADDRESSES\tUPLOAD\tDOWNLOAD\n")
	for _, row := range r.Rows {
		name := row.User
		if name == "" {
			name = "(none)"
		}
		printf(w, "%s\t%d\t%d\t%d\t%s\t%s\n", name, row.Open, row.Conn, len(row.IPs), byteSize(row.Upload), byteSize(row.Download))
		if showIPs {
			for _, ip := range row.IPs {
				printf(w, "  %s\t\t%d\t\t\t\n", ip.Addr, ip.Conns)
			}
		}
	}
	_ = w.Flush()
	// The address lines leave the last columns empty.
	for line := range strings.Lines(table.String()) {
		printf(&b, "%s\n", strings.TrimRight(line, " \n"))
	}
	if user != "" && len(r.Rows) == 0 {
		printf(&b, "no connections of %s\n", user)
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// byteSize formats n in IEC units, e.g. 1.5 GiB.
func byteSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + string("KMGTP"[exp]) + "iB"
}
