package monitor

import (
	"encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// state is what the last runs found, kept between them.
type state struct {
	Checks map[string]*checkState `json:"checks"`
	// ViaFailed is when a report last failed to leave through a node, for
	// those none has left through since.
	ViaFailed map[string]time.Time `json:"via_failed,omitzero"`
}

type checkState struct {
	// Down is the check's state; a check starts up.
	Down bool `json:"down"`
	// Streak counts the latest runs that found the opposite.
	Streak int `json:"streak,omitzero"`
	// Since is when the state began, and LastedSeconds how long the one
	// before it held.
	Since         time.Time `json:"since,omitzero"`
	LastedSeconds int64     `json:"lasted_seconds,omitzero"`
	// Detail is the latest result's.
	Detail string `json:"detail,omitzero"`
	// Told are the channels that last heard the check is down, by
	// Channel.id; the others last heard it is up, or nothing.
	Told map[string]bool `json:"told,omitzero"`
}

// tell notes that the channel has heard c's state.
func (c *checkState) tell(channel string) {
	if !c.Down {
		delete(c.Told, channel)
		return
	}
	if c.Told == nil {
		c.Told = map[string]bool{}
	}
	c.Told[channel] = true
}

// update takes a run's results into s, forgetting the checks that are
// gone. A check's state changes once confirm runs in a row disagree with
// it: one lost packet tells nothing.
func (s *state) update(results []result, skipped map[string]bool, confirm int, now time.Time) {
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.id] = true
		c := s.Checks[r.id]
		if c == nil {
			c = &checkState{Since: now}
			s.Checks[r.id] = c
		}
		if r.ok != c.Down {
			// As the state says; its detail follows the results, though.
			c.Streak = 0
			c.Detail = r.detail
			continue
		}
		if c.Streak++; c.Streak < confirm {
			continue
		}
		c.Down, c.Streak, c.Detail = !r.ok, 0, r.detail
		c.LastedSeconds, c.Since = int64(now.Sub(c.Since).Seconds()), now
	}
	for id, c := range s.Checks {
		switch {
		case seen[id]:
		case skipped[id]:
			// The runs on either side of it aren't runs in a row.
			c.Streak = 0
		default:
			delete(s.Checks, id)
		}
	}
}

// lock keeps other runs off the state at path until unlock: two at once
// would tell of the same change twice and lose each other's counts. It
// locks the directory, which stays where a file of its own would come and
// go with the state.
func lock(path string) (unlock func(), err error) {
	f, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another run is under way; --dry-run checks beside it")
		}
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

func loadState(path string) (*state, error) {
	s := &state{Checks: map[string]*checkState{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	// A file cut short by a crash starts over.
	if json.Unmarshal(data, s) != nil || s.Checks == nil {
		return &state{Checks: map[string]*checkState{}}, nil
	}
	return s, nil
}

// save replaces the file at path whole.
func (s *state) save(path string) error {
	data, err := json.Marshal(s, json.Deterministic(true))
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
