package deploy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
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

// Dial connects to addr, host:port as the host sees it, through ssh -W:
// 127.0.0.1:<port> reaches what listens on the host's loopback.
func (s *SSH) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Pipes of its own: an *os.File honours deadlines.
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_, _ = inR.Close(), inW.Close()
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "ssh", s.args("-W", addr, s.Target)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, s.Stderr
	err = cmd.Start()
	// The child holds its ends now.
	_, _ = inR.Close(), outW.Close()
	if err != nil {
		_, _ = inW.Close(), outR.Close()
		return nil, fmt.Errorf("ssh %s: %w", s.Target, err)
	}
	return &cmdConn{r: outR, w: inW, cmd: cmd, addr: addr}, nil
}

// cmdConn is a connection over a command's stdin and stdout.
type cmdConn struct {
	r, w *os.File
	cmd  *exec.Cmd
	addr string
	once sync.Once
}

func (c *cmdConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *cmdConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func (c *cmdConn) Close() error {
	c.once.Do(func() {
		_, _ = c.w.Close(), c.r.Close()
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	})
	return nil
}

func (c *cmdConn) LocalAddr() net.Addr  { return pipeAddr("ssh") }
func (c *cmdConn) RemoteAddr() net.Addr { return pipeAddr(c.addr) }

func (c *cmdConn) SetDeadline(t time.Time) error {
	return errors.Join(c.r.SetReadDeadline(t), c.w.SetWriteDeadline(t))
}
func (c *cmdConn) SetReadDeadline(t time.Time) error  { return c.r.SetReadDeadline(t) }
func (c *cmdConn) SetWriteDeadline(t time.Time) error { return c.w.SetWriteDeadline(t) }

type pipeAddr string

func (a pipeAddr) Network() string { return "ssh" }
func (a pipeAddr) String() string  { return string(a) }

func (s *SSH) args(args ...string) []string {
	return append([]string{"-o", "ControlPath=" + s.controlDir + "/%C"}, args...)
}
