package bundle

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeHost struct {
	*Host
	dir   string
	calls []string
	// fail makes a command fail, by its command line.
	fail map[string]int
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { root.Close() })
	h := &fakeHost{dir: dir, fail: map[string]int{}}
	h.Host = &Host{
		Root: root,
		Run: func(ctx context.Context, name string, args ...string) error {
			line := strings.Join(append([]string{name}, args...), " ")
			if err := ctx.Err(); err != nil {
				return err
			}
			h.calls = append(h.calls, line)
			if h.fail[line] > 0 {
				h.fail[line]--
				return errors.New(line + " failed")
			}
			return nil
		},
		// Tests can't chown to other groups.
		GroupID: func(string) (int, error) { return os.Getgid(), nil },
	}
	return h
}

func (h *fakeHost) file(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dir, p))
	require.NoError(t, err)
	return string(data)
}

func (h *fakeHost) mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(filepath.Join(h.dir, p))
	require.NoError(t, err)
	return fi.Mode().Perm()
}

func (h *fakeHost) exists(p string) bool {
	_, err := os.Lstat(filepath.Join(h.dir, p))
	return err == nil
}

const (
	unitFile = "/etc/systemd/system/princo.service"
	config   = "/var/lib/princo/files/sing-box.json"
	page     = "/var/lib/princo/files/subscription/tok/index.html"
	site     = "/etc/nginx/sites-enabled/princo.conf"
)

func node(cfg, html string) *Bundle {
	b := &Bundle{
		Format: Format,
		Node:   "de",
		Dirs:   []Dir{{Path: "/var/lib/princo/files", Mode: 0o751}},
		Files: []File{
			{Path: unitFile, Mode: 0o644, Data: []byte("[Service]\n")},
			{Path: config, Mode: 0o600, Data: []byte(cfg)},
			{Path: site, Mode: 0o644, Data: []byte("server {}\n")},
		},
		Units: []Unit{
			{Name: "nginx.service", Files: []string{site}, Reload: true, Check: []string{"nginx", "-t"}},
			{Name: "princo.service", Files: []string{unitFile, config}},
		},
	}
	if html != "" {
		b.Files = append(b.Files, File{Path: page, Mode: 0o640, Group: "www-data", Data: []byte(html)})
		b.Units[0].Files = append(b.Units[0].Files, page)
	}
	return b
}

func TestApply_Fresh(t *testing.T) {
	h := newFakeHost(t)
	changes, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)
	require.Equal(t, []Change{
		{Create, "/var/lib/princo/files/"},
		{Create, unitFile},
		{Create, config},
		{Create, site},
		{Create, page},
	}, changes)
	require.Equal(t, `{"a":1}`, h.file(t, config))
	require.Equal(t, fs.FileMode(0o600), h.mode(t, config))
	require.Equal(t, fs.FileMode(0o640), h.mode(t, page))
	require.Equal(t, fs.FileMode(0o751), h.mode(t, "/var/lib/princo/files"))
	require.Equal(t, []string{
		"systemctl daemon-reload",
		"systemctl enable --quiet nginx.service",
		"systemctl enable --quiet princo.service",
		"nginx -t",
		"systemctl reload-or-restart nginx.service",
		"systemctl restart princo.service",
		"systemctl is-active --quiet nginx.service",
		"systemctl is-active --quiet princo.service",
	}, h.calls)
}

func TestApply_DirParents(t *testing.T) {
	h := newFakeHost(t)
	b := node(`{"a":1}`, "")
	b.Dirs[0].Mode = 0o700
	_, err := h.Apply(t.Context(), b)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o700), h.mode(t, "/var/lib/princo/files"))
	require.Equal(t, fs.FileMode(0o755), h.mode(t, "/var/lib/princo"), "others pass through to the rest of it")
}

func TestApply_Umask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o755), h.mode(t, "/var/lib/princo/files/subscription/tok"))
	require.Equal(t, fs.FileMode(0o640), h.mode(t, page))
	require.Equal(t, fs.FileMode(0o600), h.mode(t, StateFile), "the site's paths hold the users' tokens")
}

func TestApply_Unchanged(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)
	h.calls = nil

	changes, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)
	require.Empty(t, changes)
	require.Equal(t, []string{
		"systemctl enable --quiet nginx.service",
		"systemctl enable --quiet princo.service",
		"systemctl start nginx.service",
		"systemctl start princo.service",
	}, h.calls)
}

func TestApply_ChangedConfig(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)
	h.calls = nil

	changes, err := h.Apply(t.Context(), node(`{"a":2}`, "<html>"))
	require.NoError(t, err)
	require.Equal(t, []Change{{Update, config}}, changes)
	require.Equal(t, []string{
		"systemctl enable --quiet nginx.service",
		"systemctl enable --quiet princo.service",
		"systemctl start nginx.service",
		"systemctl restart princo.service",
		"systemctl is-active --quiet princo.service",
	}, h.calls, "no daemon-reload, and nginx's check runs only when its files change")
}

func TestApply_ReloadsUnlessUnitChanged(t *testing.T) {
	reloading := func(cfg, unit string) *Bundle {
		b := node(cfg, "")
		b.Files[0].Data = []byte(unit)
		b.Units[1].Reload = true
		return b
	}
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), reloading(`{"a":1}`, "[Service]\n"))
	require.NoError(t, err)

	h.calls = nil
	_, err = h.Apply(t.Context(), reloading(`{"a":2}`, "[Service]\n"))
	require.NoError(t, err)
	require.Contains(t, h.calls, "systemctl reload-or-restart princo.service", "a new config reloads")

	h.calls = nil
	_, err = h.Apply(t.Context(), reloading(`{"a":2}`, "[Service]\nExecStart=/new\n"))
	require.NoError(t, err)
	require.Contains(t, h.calls, "systemctl restart princo.service", "a new unit restarts: a reload keeps the old process")
}

func TestApply_ModeDrift(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Join(h.dir, config), 0o644))
	require.NoError(t, os.Chmod(filepath.Join(h.dir, "/var/lib/princo/files"), 0o755))

	changes, err := h.Diff(node(`{"a":1}`, ""))
	require.NoError(t, err)
	require.Equal(t, []Change{{Update, "/var/lib/princo/files/"}, {Update, config}}, changes)
	_, err = h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o600), h.mode(t, config))
	require.Equal(t, fs.FileMode(0o751), h.mode(t, "/var/lib/princo/files"))
}

func TestApply_RemovesDropped(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)
	h.calls = nil

	changes, err := h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
	require.Equal(t, []Change{{Remove, page}}, changes)
	require.False(t, h.exists(page))
	require.False(t, h.exists("/var/lib/princo/files/subscription"), "empty directories are pruned")
	require.True(t, h.exists("/var/lib/princo/files"))
}

func TestApply_Partial(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)

	partial := &Bundle{
		Format:  Format,
		Node:    "de",
		Partial: true,
		Files:   []File{{Path: site, Mode: 0o644, Data: []byte("server { acme }\n")}},
		Units:   []Unit{{Name: "nginx.service", Files: []string{site}, Reload: true}},
	}
	changes, err := h.Apply(t.Context(), partial)
	require.NoError(t, err)
	require.Equal(t, []Change{{Update, site}}, changes)
	require.True(t, h.exists(page), "a partial bundle removes nothing")

	changes, err = h.Diff(node(`{"a":1}`, ""))
	require.NoError(t, err)
	require.Equal(t, []Change{{Update, site}, {Remove, page}}, changes, "the whole bundle before it is still on record")
}

func TestApply_CheckFails(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, "<html>"))
	require.NoError(t, err)
	h.calls = nil
	h.fail["nginx -t"] = 1

	_, err = h.Apply(t.Context(), node(`{"a":2}`, "<html v2>"))
	require.ErrorContains(t, err, "check of nginx.service: nginx -t failed; the old files are back")
	require.Equal(t, `{"a":1}`, h.file(t, config))
	require.Equal(t, "<html>", h.file(t, page))
	require.Equal(t, []string{
		"systemctl enable --quiet nginx.service",
		"systemctl enable --quiet princo.service",
		"nginx -t",
		"systemctl reload-or-restart nginx.service",
		"systemctl restart princo.service",
	}, h.calls)
}

func TestApply_RestartFails(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
	h.calls = nil
	h.fail["systemctl restart princo.service"] = 1

	_, err = h.Apply(t.Context(), node(`{"bad":true}`, "<html>"))
	require.ErrorContains(t, err, "systemctl restart princo.service failed; the old files are back")
	require.Equal(t, `{"a":1}`, h.file(t, config))
	require.False(t, h.exists(page), "a file the failed apply created is gone")
	require.Equal(t, "systemctl restart princo.service", h.calls[len(h.calls)-1], "the engine runs on the old config again")

	changes, err := h.Diff(node(`{"a":1}`, ""))
	require.NoError(t, err)
	require.Empty(t, changes, "the failed apply left no state behind")
}

func TestApply_StopsAfterRestart(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
	h.calls = nil
	h.fail["systemctl is-active --quiet princo.service"] = 1

	_, err = h.Apply(t.Context(), node(`{"port":"taken"}`, ""))
	require.ErrorContains(t, err, "princo.service stopped after it restarted; see journalctl -u princo.service; the old files are back")
	require.Equal(t, `{"a":1}`, h.file(t, config))
	require.Equal(t, "systemctl restart princo.service", h.calls[len(h.calls)-1])
}

func TestApply_Cancelled(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
	h.calls = nil

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.Settle = time.Hour
	_, err = h.Apply(ctx, node(`{"a":2}`, ""))
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, `{"a":1}`, h.file(t, config))
	require.Equal(t, []string{"systemctl restart princo.service"}, h.calls, "the rollback runs all the same")
}

func TestApply_Locked(t *testing.T) {
	h := newFakeHost(t)
	unlock, err := h.lock()
	require.NoError(t, err)

	other := newFakeHost(t)
	other.Root = h.Root
	_, err = other.Apply(t.Context(), node(`{"a":1}`, ""))
	require.ErrorContains(t, err, "another princo host apply is running")
	require.False(t, h.exists(config))

	unlock()
	_, err = other.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
}

func TestApply_OtherNode(t *testing.T) {
	h := newFakeHost(t)
	_, err := h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.NoError(t, err)
	b := node(`{"a":1}`, "")
	b.Node = "us"
	_, err = h.Apply(t.Context(), b)
	require.ErrorContains(t, err, "this host runs node de, not us")
}

func TestDiff_ChangesNothing(t *testing.T) {
	h := newFakeHost(t)
	changes, err := h.Diff(node(`{"a":1}`, ""))
	require.NoError(t, err)
	require.Len(t, changes, 4)
	require.False(t, h.exists("/var/lib/princo"))
	require.Empty(t, h.calls)
}

func TestApply_RefusesNonRegular(t *testing.T) {
	h := newFakeHost(t)
	require.NoError(t, os.MkdirAll(filepath.Join(h.dir, config), 0o755))
	_, err := h.Apply(t.Context(), node(`{"a":1}`, ""))
	require.ErrorContains(t, err, config+" isn't a regular file")
}

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*Bundle)
		err  string
	}{
		"format":    {func(b *Bundle) { b.Format = 99 }, "bundle format 99, but this princo applies format 1"},
		"relative":  {func(b *Bundle) { b.Files[0].Path = "etc/x" }, `path "etc/x" isn't absolute and clean`},
		"unclean":   {func(b *Bundle) { b.Files[0].Path = "/etc/../x" }, `path "/etc/../x" isn't absolute and clean`},
		"duplicate": {func(b *Bundle) { b.Files[1].Path = b.Files[0].Path }, unitFile + " appears twice"},
		"mode":      {func(b *Bundle) { b.Files[0].Mode = 0o4755 }, "only permission bits"},
		"unit file": {func(b *Bundle) { b.Units[1].Files = []string{"/nope"} }, "unit princo.service runs from /nope, which the bundle lacks"},
	} {
		t.Run(name, func(t *testing.T) {
			b := node(`{}`, "")
			tc.edit(b)
			require.ErrorContains(t, b.validate(), tc.err)
		})
	}
}
