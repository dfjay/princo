package monitor

import (
	"encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// threshold is how many runs in a row must disagree with a check's state
// to change it: one lost packet tells nothing.
const threshold = 2

// state is what the last runs found, kept between them.
type state struct {
	Checks map[string]*checkState `json:"checks"`
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
	// Reported is the state Telegram last heard of.
	Reported bool `json:"reported"`
}

// update takes a run's results into s, forgetting the checks that are gone.
func (s *state) update(results []result, skipped map[string]bool, now time.Time) {
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
		if c.Streak++; c.Streak < threshold {
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
