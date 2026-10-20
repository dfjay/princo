package bundle

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// StateDir is princo's directory on a host. Removing a file prunes the
// directories it leaves empty, up to StateDir.
const StateDir = "/var/lib/princo"

// StateFile lists the files of the last apply, to remove those the next
// one lacks.
const StateFile = StateDir + "/applied.json"

const systemdDir = "/etc/systemd/system/"

type Op byte

const (
	Create Op = '+'
	Update Op = '~'
	Remove Op = '-'
)

// Change is a file or directory, whose path ends in a slash, that an
// apply creates, updates or removes.
type Change struct {
	Op   Op
	Path string
}

func (c Change) String() string { return string(c.Op) + " " + c.Path }

// Host applies bundles to a file tree, "/" on a real host.
type Host struct {
	Root *os.Root
	// Run runs systemctl and the units' checks.
	Run func(ctx context.Context, name string, args ...string) error
	// GroupID resolves a group name; "" is root.
	GroupID func(name string) (int, error)
}

func NewHost() (*Host, error) {
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	return &Host{Root: root, Run: run, GroupID: groupID}, nil
}

func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", strings.Join(append([]string{name}, args...), " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func groupID(name string) (int, error) {
	if name == "" {
		return 0, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

type state struct {
	Node  string   `json:"node"`
	Files []string `json:"files"`
}

// entry is a regular file's content and attributes, or its absence.
type entry struct {
	exists bool
	data   []byte
	mode   fs.FileMode
	gid    int
}

func (e entry) equal(o entry) bool {
	return e.exists == o.exists && bytes.Equal(e.data, o.data) && e.mode == o.mode && e.gid == o.gid
}

type fileChange struct {
	path     string
	old, new entry
}

type prepared struct {
	changes []Change
	files   []fileChange
}

// Diff is what Apply would change, without changing anything.
func (h *Host) Diff(b *Bundle) ([]Change, error) {
	p, err := h.prepare(b)
	if err != nil {
		return nil, err
	}
	return p.changes, nil
}

// Apply writes b, removes the files of the last apply that b lacks, and
// restarts the units whose files changed; it starts the others. When a
// check or a restart fails, the old files go back and the units restart
// on them.
func (h *Host) Apply(ctx context.Context, b *Bundle) ([]Change, error) {
	p, err := h.prepare(b)
	if err != nil {
		return nil, err
	}
	for _, d := range b.Dirs {
		if err := h.makeDir(d); err != nil {
			return nil, err
		}
	}
	changed := map[string]bool{}
	for i, fc := range p.files {
		if err := h.put(fc.path, fc.new); err != nil {
			return nil, errors.Join(err, h.undo(p.files[:i]))
		}
		changed[fc.path] = true
	}
	if err := h.activate(ctx, b.Units, changed); err != nil {
		if uerr := h.undo(p.files); uerr != nil {
			return nil, errors.Join(err, fmt.Errorf("putting the old files back: %w", uerr))
		}
		if rerr := h.restart(ctx, b.Units, changed); rerr != nil {
			return nil, errors.Join(err, fmt.Errorf("the old files are back, but: %w", rerr))
		}
		return nil, fmt.Errorf("%w; the old files are back", err)
	}
	if !b.Partial {
		if err := h.saveState(b); err != nil {
			return nil, err
		}
	}
	return p.changes, nil
}

func (h *Host) prepare(b *Bundle) (*prepared, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	st, err := h.loadState()
	if err != nil {
		return nil, err
	}
	if st.Node != "" && st.Node != b.Node {
		return nil, OtherNodeError(st.Node, b.Node)
	}

	p := &prepared{}
	for _, d := range b.Dirs {
		gid, err := h.GroupID(d.Group)
		if err != nil {
			return nil, fmt.Errorf("%s: group %s: %w", d.Path, d.Group, err)
		}
		fi, err := h.Root.Lstat(rel(d.Path))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			p.changes = append(p.changes, Change{Create, d.Path + "/"})
		case err != nil:
			return nil, err
		case !fi.IsDir():
			return nil, fmt.Errorf("%s isn't a directory", d.Path)
		case fi.Mode().Perm() != d.Mode || gidOf(fi) != gid:
			p.changes = append(p.changes, Change{Update, d.Path + "/"})
		}
	}

	wanted := map[string]bool{}
	for _, f := range b.Files {
		wanted[f.Path] = true
		gid, err := h.GroupID(f.Group)
		if err != nil {
			return nil, fmt.Errorf("%s: group %s: %w", f.Path, f.Group, err)
		}
		want := entry{exists: true, data: f.Data, mode: f.Mode, gid: gid}
		old, err := h.read(f.Path)
		if err != nil {
			return nil, err
		}
		if old.equal(want) {
			continue
		}
		op := Update
		if !old.exists {
			op = Create
		}
		p.changes = append(p.changes, Change{op, f.Path})
		p.files = append(p.files, fileChange{f.Path, old, want})
	}
	if b.Partial {
		return p, nil
	}
	for _, f := range st.Files {
		if wanted[f] {
			continue
		}
		old, err := h.read(f)
		if err != nil {
			return nil, err
		}
		if old.exists {
			p.changes = append(p.changes, Change{Remove, f})
			p.files = append(p.files, fileChange{f, old, entry{}})
		}
	}
	return p, nil
}

func (h *Host) activate(ctx context.Context, units []Unit, changed map[string]bool) error {
	if err := h.daemonReload(ctx, changed); err != nil {
		return err
	}
	for _, u := range units {
		if err := h.Run(ctx, "systemctl", "enable", "--quiet", u.Name); err != nil {
			return err
		}
	}
	for _, u := range units {
		if touched(u, changed) && len(u.Check) > 0 {
			if err := h.Run(ctx, u.Check[0], u.Check[1:]...); err != nil {
				return fmt.Errorf("check of %s: %w", u.Name, err)
			}
		}
	}
	for _, u := range units {
		var err error
		if touched(u, changed) {
			err = h.restartUnit(ctx, u)
		} else {
			err = h.Run(ctx, "systemctl", "start", u.Name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// restart brings the units whose files changed back onto the old files.
func (h *Host) restart(ctx context.Context, units []Unit, changed map[string]bool) error {
	errs := []error{h.daemonReload(ctx, changed)}
	for _, u := range units {
		if touched(u, changed) {
			errs = append(errs, h.restartUnit(ctx, u))
		}
	}
	return errors.Join(errs...)
}

func (h *Host) restartUnit(ctx context.Context, u Unit) error {
	if u.Reload {
		return h.Run(ctx, "systemctl", "reload-or-restart", u.Name)
	}
	return h.Run(ctx, "systemctl", "restart", u.Name)
}

func (h *Host) daemonReload(ctx context.Context, changed map[string]bool) error {
	for p := range changed {
		if strings.HasPrefix(p, systemdDir) {
			return h.Run(ctx, "systemctl", "daemon-reload")
		}
	}
	return nil
}

func touched(u Unit, changed map[string]bool) bool {
	for _, f := range u.Files {
		if changed[f] {
			return true
		}
	}
	return false
}

// undo puts the files back as they were, last change first.
func (h *Host) undo(files []fileChange) error {
	var errs []error
	for _, fc := range slices.Backward(files) {
		errs = append(errs, h.put(fc.path, fc.old))
	}
	return errors.Join(errs...)
}

func (h *Host) read(p string) (entry, error) {
	fi, err := h.Root.Lstat(rel(p))
	if errors.Is(err, fs.ErrNotExist) {
		return entry{}, nil
	}
	if err != nil {
		return entry{}, err
	}
	if !fi.Mode().IsRegular() {
		return entry{}, fmt.Errorf("%s isn't a regular file", p)
	}
	data, err := h.Root.ReadFile(rel(p))
	if err != nil {
		return entry{}, err
	}
	return entry{exists: true, data: data, mode: fi.Mode().Perm(), gid: gidOf(fi)}, nil
}

// put writes e to p, or removes p when e doesn't exist.
func (h *Host) put(p string, e entry) error {
	if !e.exists {
		return h.remove(p)
	}
	r := rel(p)
	if err := h.mkdirs(path.Dir(r)); err != nil {
		return err
	}
	tmp := path.Join(path.Dir(r), "."+path.Base(r)+".princo-new")
	f, err := h.Root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(e.data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = h.Root.Chmod(tmp, e.mode)
	}
	if err == nil {
		err = h.Root.Chown(tmp, -1, e.gid)
	}
	if err == nil {
		err = h.Root.Rename(tmp, r)
	}
	if err != nil {
		_ = h.Root.Remove(tmp)
		return fmt.Errorf("write %s: %w", p, err)
	}
	return nil
}

func (h *Host) remove(p string) error {
	if err := h.Root.Remove(rel(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for dir := path.Dir(p); strings.HasPrefix(dir, StateDir+"/"); dir = path.Dir(dir) {
		if h.Root.Remove(rel(dir)) != nil {
			break
		}
	}
	return nil
}

func (h *Host) makeDir(d Dir) error {
	gid, err := h.GroupID(d.Group)
	if err != nil {
		return err
	}
	r := rel(d.Path)
	if err := h.mkdirs(path.Dir(r)); err != nil {
		return err
	}
	if err := h.Root.Mkdir(r, d.Mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := h.Root.Chmod(r, d.Mode); err != nil {
		return err
	}
	return h.Root.Chown(r, -1, gid)
}

// mkdirs makes dir and its missing parents 0755, whatever the umask.
func (h *Host) mkdirs(dir string) error {
	if _, err := h.Root.Lstat(dir); err == nil || dir == "." {
		return nil
	}
	if err := h.mkdirs(path.Dir(dir)); err != nil {
		return err
	}
	if err := h.Root.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return h.Root.Chmod(dir, 0o755)
}

func (h *Host) loadState() (state, error) {
	var st state
	data, err := h.Root.ReadFile(rel(StateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("%s: %w", StateFile, err)
	}
	return st, nil
}

func (h *Host) saveState(b *Bundle) error {
	st := state{Node: b.Node, Files: make([]string, len(b.Files))}
	for i, f := range b.Files {
		st.Files[i] = f.Path
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	gid, err := h.GroupID("")
	if err != nil {
		return err
	}
	// The site's paths hold the users' tokens.
	return h.put(StateFile, entry{exists: true, data: append(data, '\n'), mode: 0o600, gid: gid})
}

// OtherNodeError refuses to put node on a host that runs another.
func OtherNodeError(running, node string) error {
	return fmt.Errorf("this host runs node %s, not %s; remove %s to put another node here", running, node, StateFile)
}

// rel is p for os.Root, which takes no absolute paths.
func rel(p string) string { return strings.TrimPrefix(p, "/") }

func gidOf(fi fs.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Gid)
	}
	return -1
}
