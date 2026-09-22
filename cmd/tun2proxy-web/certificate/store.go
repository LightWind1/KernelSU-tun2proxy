package certificate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Entry struct {
	Certificate
	Source    string    `json:"source"`
	Managed   bool      `json:"managed"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
type Remote struct {
	LocalID   string    `json:"localID"`
	RemoteID  string    `json:"remoteID"`
	Endpoint  string    `json:"endpoint"`
	CheckedAt time.Time `json:"checkedAt"`
	History   []string  `json:"history,omitempty"`
}
type Inventory struct {
	Version int               `json:"version"`
	Entries map[string]Entry  `json:"entries"`
	Yakit   map[string]Remote `json:"yakit"`
}
type Store struct{ Dir string }

func Atomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".stage-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	if d, e := os.Open(filepath.Dir(path)); e == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
func (s Store) Load() (Inventory, error) {
	v := Inventory{Version: 1, Entries: map[string]Entry{}, Yakit: map[string]Remote{}}
	b, e := os.ReadFile(filepath.Join(s.Dir, "inventory.json"))
	if os.IsNotExist(e) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal(b, &v); e != nil {
		return v, e
	}
	if v.Version != 1 || v.Entries == nil || v.Yakit == nil {
		return v, errors.New("invalid certificate inventory")
	}
	for id, e := range v.Entries {
		if !ValidID(id) || e.ID != id {
			return v, errors.New("invalid inventory ID")
		}
	}
	return v, nil
}
func (s Store) Save(v Inventory) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return Atomic(filepath.Join(s.Dir, "inventory.json"), b)
}
func (s Store) Path(id string) (string, error) {
	if !ValidID(id) {
		return "", errors.New("invalid certificate ID")
	}
	return filepath.Join(s.Dir, "objects", id+".pem"), nil
}
func (s Store) Read(id string) (Certificate, error) {
	p, e := s.Path(id)
	if e != nil {
		return Certificate{}, e
	}
	st, e := os.Lstat(p)
	if e != nil {
		return Certificate{}, e
	}
	if !st.Mode().IsRegular() {
		return Certificate{}, errors.New("certificate object must be a regular file")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return Certificate{}, e
	}
	c, e := Parse(b)
	if e == nil && c.ID != id {
		e = errors.New("certificate fingerprint mismatch")
	}
	return c, e
}

// Put writes immutable, content-addressed data before inventory is committed.
// Failed transactions may leave harmless unreferenced public objects, never lose the old CA.
func (s Store) Put(v *Inventory, c Certificate, source string) (Entry, error) {
	if !ValidID(c.ID) {
		return Entry{}, errors.New("invalid certificate ID")
	}
	if e, ok := v.Entries[c.ID]; ok {
		return e, nil
	}
	p, _ := s.Path(c.ID)
	if err := Atomic(p, c.PEM()); err != nil {
		return Entry{}, err
	}
	now := time.Now().UTC()
	e := Entry{Certificate: c, Source: source, CreatedAt: now, UpdatedAt: now}
	v.Entries[c.ID] = e
	return e, nil
}
func (s Store) Delete(v *Inventory, id string) error {
	if !ValidID(id) {
		return errors.New("invalid certificate ID")
	}
	e, ok := v.Entries[id]
	if !ok {
		return errors.New("certificate not found")
	}
	if e.Managed {
		return errors.New("remove from system before deleting cache")
	}
	for k, r := range v.Yakit {
		if r.LocalID == id {
			r.LocalID = ""
		}
		history := r.History[:0]
		for _, prior := range r.History {
			if prior != id {
				history = append(history, prior)
			}
		}
		r.History = history
		v.Yakit[k] = r
	}
	delete(v.Entries, id)
	// Persist first: interrupted cleanup cannot leave a dangling inventory entry.
	if err := s.Save(*v); err != nil {
		return err
	}
	p, _ := s.Path(id)
	return os.Remove(p)
}
func Entries(v Inventory) []Entry {
	out := []Entry{}
	for _, e := range v.Entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
