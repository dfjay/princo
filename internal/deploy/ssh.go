package deploy

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// SSH runs scripts on a node's host with the system ssh, so the operator's
// ~/.ssh/config, agent and known_hosts apply. Every script goes over one
// connection, opened by Open.
type SSH struct {
	// Target is user@host, or a Host of ~/.ssh/config.
	Target string
	Stderr io.Writer

	controlDir string
}

// Open connects to the host; Close disconnects.
func (s *SSH) Open(ctx context.Context) error {
	if s.Target == "" || strings.HasPrefix(s.Target, "-") {
		return fmt.Errorf("bad ssh target %q", s.Target)
	}
	// Not in $TMPDIR: on macOS its path is too long for a socket.
	dir, err := os.MkdirTemp("/tmp", "princo-ssh-")
	if err != nil {
		return err
	}
	s.controlDir = dir
	// The master stays in the background without our stdout and stderr:
	// were they pipes, every later command would wait for it to exit.
	cmd := exec.CommandContext(ctx, "ssh", s.args("-o", "ControlMaster=yes", "-o", "ControlPersist=yes", "-f", "-N", s.Target)...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("ssh %s: %w", s.Target, err)
	}
	return nil
}

func (s *SSH) Close() error {
	_ = exec.Command("ssh", s.args("-O", "exit", s.Target)...).Run()
	return os.RemoveAll(s.controlDir)
}

// Run runs script with sh as root, through sudo -n when the SSH user
// isn't root.
func (s *SSH) Run(ctx context.Context, script string, stdin io.Reader, stdout io.Writer) error {
	// A script that reads no stdin goes there: through the control socket
	// macOS refuses a command line of about 8 KB.
	sh := "sh -s"
	if stdin == nil {
		stdin = strings.NewReader(script)
	} else {
		sh = "sh -c " + shellQuote(script)
	}
	line := `if [ "$(id -u)" -eq 0 ]; then set --; else set -- sudo -n; fi; exec "$@" ` + sh
	cmd := exec.CommandContext(ctx, "ssh", s.args(s.Target, line)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, s.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh %s: %w", s.Target, err)
	}
	return nil
}

func (s *SSH) args(args ...string) []string {
	return append([]string{"-o", "ControlPath=" + s.controlDir + "/%C"}, args...)
}
