package deploy

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// SSH runs scripts on a host over one connection of the system ssh, so
// ~/.ssh/config, the agent and known_hosts apply.
type SSH struct {
	// Target is user@host or a Host of ~/.ssh/config.
	Target string
	Stderr io.Writer

	controlDir string
}

func (s *SSH) Open(ctx context.Context) error {
	if s.Target == "" || strings.HasPrefix(s.Target, "-") {
		return fmt.Errorf("bad ssh target %q", s.Target)
	}
	// macOS's $TMPDIR is too long for a socket path.
	dir, err := os.MkdirTemp("/tmp", "princo-ssh-")
	if err != nil {
		return err
	}
	s.controlDir = dir
	// No pipes of ours in the backgrounded master, or commands wait on it;
	// it outlives a missed Close by a minute.
	cmd := exec.CommandContext(ctx, "ssh", s.args("-o", "ControlMaster=yes", "-o", "ControlPersist=60", "-f", "-N", s.Target)...)
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

// Run runs script as root, through sudo -n for other users.
func (s *SSH) Run(ctx context.Context, script string, stdin io.Reader, stdout io.Writer) error {
	// Over the control socket, macOS refuses command lines of about 8 KB.
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
