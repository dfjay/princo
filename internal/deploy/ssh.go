package deploy

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// SSH runs commands on a node's host with the system ssh, so the
// operator's ~/.ssh/config, agent and known_hosts apply.
type SSH struct {
	// Target is user@host, or a Host of ~/.ssh/config.
	Target         string
	Stdout, Stderr io.Writer
}

// AsRoot runs a shell command line as root on the host, through sudo -n
// when the SSH user isn't root.
func (s SSH) AsRoot(ctx context.Context, stdin io.Reader, command string) error {
	if s.Target == "" || strings.HasPrefix(s.Target, "-") {
		return fmt.Errorf("bad ssh target %q", s.Target)
	}
	line := `if [ "$(id -u)" -eq 0 ]; then ` + command + `; else sudo -n ` + command + `; fi`
	cmd := exec.CommandContext(ctx, "ssh", s.Target, line)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, s.Stdout, s.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh %s: %w", s.Target, err)
	}
	return nil
}
