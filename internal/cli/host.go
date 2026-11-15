package cli

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/dfjay/princo/internal/bundle"
	"github.com/dfjay/princo/internal/deploy"
	"github.com/dfjay/princo/internal/engineapi"
	"github.com/dfjay/princo/internal/host"
	"github.com/dfjay/princo/internal/monitor"
)

func newHostCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Commands princo deploy runs on a node's host",
	}
	cmd.AddCommand(newHostApplyCommand())
	cmd.AddCommand(newHostMonitorCommand())
	return cmd
}

// monitorTimeout ends a run before the timer's shortest interval is over,
// and leaves it its longest check and the channels' time.
const monitorTimeout = 55 * time.Second

func newHostMonitorCommand() *cobra.Command {
	var configPath, statePath string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Check this node and report what changed",
		Long: `Run the checks of a fleet with monitor: on this node: that its engine
runs, its certificates aren't about to expire, WARP passes traffic and, on
the nodes monitor.reach selects, that other nodes answer. A check changes
state once monitor.confirm runs in a row find it so; each channel of
monitor.notify then hears of it, once. A deploy runs it on a timer; run it with --dry-run
to see what the checks find now.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(configPath)
			if err != nil {
				return err
			}
			var cfg monitor.Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				return fmt.Errorf("%s: %w", configPath, err)
			}
			ctx, stop := interruptible(cmd.Context())
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, monitorTimeout)
			defer cancel()
			m := &monitor.Monitor{
				Config:    &cfg,
				StatePath: statePath,
				Out:       cmd.OutOrStdout(),
				Now:       time.Now,
				HTTP:      &http.Client{Timeout: 15 * time.Second, Transport: transport(nil)},
				Dial:      (&net.Dialer{}).DialContext,
				Active: func(ctx context.Context, unit string) error {
					return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run()
				},
			}
			if p := cfg.Proxy; p != nil {
				m.Via = func(node string) *http.Client {
					return &http.Client{Transport: transport(p.URL(node))}
				}
			}
			if cfg.Warp != nil {
				m.Engine = &engineapi.Client{HTTP: &http.Client{}, URL: cfg.Warp.URL, Secret: cfg.Warp.Secret}
			}
			return m.Run(ctx, dryRun)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", path.Join(deploy.FilesDir, host.MonitorFile), "The node's rendered "+host.MonitorFile)
	cmd.Flags().StringVar(&statePath, "state", deploy.MonitorState, "File that keeps the checks' states between runs")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what the checks find; tell no one, keep no state")
	return cmd
}

// transport reaches a channel through proxy, or directly when it is nil,
// whatever proxy the environment names. A run is too short to keep
// connections for.
func transport(proxy *url.URL) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy, t.DisableKeepAlives = http.ProxyURL(proxy), true
	return t
}

func newHostApplyCommand() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a bundle read from stdin to this host",
		Long: `Read a bundle that princo deploy built from stdin, write its files,
remove the files the previous bundle had and this one lacks, and restart
the systemd units whose files changed. When a check or a restart fails,
the old files are put back and the units restarted on them. Run it as
root; it prints what it changed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var b bundle.Bundle
			if err := json.UnmarshalRead(cmd.InOrStdin(), &b); err != nil {
				return fmt.Errorf("read bundle: %w", err)
			}
			h, err := bundle.NewHost()
			if err != nil {
				return err
			}
			defer h.Root.Close()
			var changes []bundle.Change
			if check {
				changes, err = h.Diff(&b)
			} else {
				ctx, stop := interruptible(cmd.Context())
				defer stop()
				changes, err = h.Apply(ctx, &b)
			}
			if err != nil {
				return err
			}
			for _, c := range changes {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), c); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Print what would change, and change nothing")
	return cmd
}

// interruptible cancels ctx on a signal instead of exiting, for commands
// that clean up; ^C wouldn't stop one reading a terminal.
func interruptible(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}
