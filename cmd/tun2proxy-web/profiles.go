package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"tun2proxy-web/certificate"
)

// The legacy config.json remains the engine's active configuration. Profiles
// are a separate private index; no second proxy host/port is stored.
type ConnectionProfile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Config Config `json:"config"`
}
type ProfileSet struct {
	Version  int                 `json:"version"`
	ActiveID string              `json:"activeId"`
	Profiles []ConnectionProfile `json:"profiles"`
}

var profileMu sync.Mutex

func profilePath() string { return filepath.Join(filepath.Dir(configFile), "profiles.json") }
func newProfileID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func readProfiles() (ProfileSet, error) {
	b, e := os.ReadFile(profilePath())
	if os.IsNotExist(e) {
		cfg, e := loadConfig()
		if e != nil {
			return ProfileSet{}, e
		}
		return ProfileSet{Version: 1, ActiveID: "default", Profiles: []ConnectionProfile{{ID: "default", Name: "默认电脑", Config: cfg}}}, nil
	}
	if e != nil {
		return ProfileSet{}, e
	}
	var p ProfileSet
	if e = json.Unmarshal(b, &p); e != nil {
		return p, e
	}
	if p.Version != 1 || len(p.Profiles) == 0 {
		return p, errors.New("invalid profiles index")
	}
	found := false
	ids := map[string]bool{}
	for _, v := range p.Profiles {
		if v.ID == "" || ids[v.ID] || v.Name == "" {
			return p, errors.New("invalid profile")
		}
		ids[v.ID] = true
		if v.ID == p.ActiveID {
			found = true
		}
	}
	if !found {
		return p, errors.New("active profile missing")
	}
	return p, nil
}
func writeProfiles(p ProfileSet) error {
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		return e
	}
	return certificate.Atomic(profilePath(), b)
}

// Kept in this package to use the certificate store's atomic-write semantics.
func profileByID(p ProfileSet, id string) (ConnectionProfile, bool) {
	for _, v := range p.Profiles {
		if v.ID == id {
			return v, true
		}
	}
	return ConnectionProfile{}, false
}
func validateProfileConfig(c Config) error {
	u, e := url.Parse(c.ProxyURL)
	if e != nil || u.Hostname() == "" || u.Port() == "" {
		return errors.New("invalid proxy URL")
	}
	if u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return errors.New("unsupported proxy type")
	}
	return nil
}
func apiProfiles(w http.ResponseWriter, r *http.Request) {
	profileMu.Lock()
	defer profileMu.Unlock()
	p, e := readProfiles()
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	if r.Method == "GET" {
		writeJSON(w, 200, p)
		return
	}
	if r.Method != "POST" {
		writeError(w, 405, "Use GET or POST")
		return
	}
	var a struct {
		Action string `json:"action"`
		ID     string `json:"id"`
		Name   string `json:"name"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&a) != nil {
		writeError(w, 400, "Invalid request")
		return
	}
	a.Name = strings.TrimSpace(a.Name)
	switch a.Action {
	case "create":
		if a.Name == "" || len([]rune(a.Name)) > 64 {
			writeError(w, 400, "Name must contain 1-64 characters")
			return
		}
		active, _ := profileByID(p, p.ActiveID)
		cfg := active.Config
		cfg.ProxyURL = "http://127.0.0.1:8083"
		p.Profiles = append(p.Profiles, ConnectionProfile{ID: newProfileID(), Name: a.Name, Config: cfg})
	case "clone":
		if a.Name == "" || len([]rune(a.Name)) > 64 {
			writeError(w, 400, "Name must contain 1-64 characters")
			return
		}
		active, _ := profileByID(p, p.ActiveID)
		p.Profiles = append(p.Profiles, ConnectionProfile{ID: newProfileID(), Name: a.Name, Config: active.Config})
	case "rename":
		if a.Name == "" || len([]rune(a.Name)) > 64 {
			writeError(w, 400, "Name must contain 1-64 characters")
			return
		}
		ok := false
		for i := range p.Profiles {
			if p.Profiles[i].ID == a.ID {
				p.Profiles[i].Name = a.Name
				ok = true
			}
		}
		if !ok {
			writeError(w, 404, "Profile not found")
			return
		}
	case "delete":
		if a.ID == p.ActiveID {
			writeError(w, 409, "Switch before deleting the active profile")
			return
		}
		if len(p.Profiles) == 1 {
			writeError(w, 409, "Cannot delete the last profile")
			return
		}
		next := make([]ConnectionProfile, 0, len(p.Profiles)-1)
		for _, v := range p.Profiles {
			if v.ID != a.ID {
				next = append(next, v)
			}
		}
		if len(next) == len(p.Profiles) {
			writeError(w, 404, "Profile not found")
			return
		}
		p.Profiles = next
	case "select":
		target, ok := profileByID(p, a.ID)
		if !ok {
			writeError(w, 404, "Profile not found")
			return
		}
		if e = validateProfileConfig(target.Config); e != nil {
			writeError(w, 400, e.Error())
			return
		}
		if a.ID != p.ActiveID {
			lifecycleMu.Lock()
			defer lifecycleMu.Unlock()
			if getProcessStatus().Running {
				writeError(w, 409, "Stop the running proxy before switching computers")
				return
			}
			old, e := loadConfig()
			if e != nil {
				writeError(w, 500, e.Error())
				return
			}
			if e = saveRuntimeConfig(target.Config); e != nil {
				writeError(w, 500, e.Error())
				return
			}
			p.ActiveID = a.ID
			if e = writeProfiles(p); e != nil {
				_ = saveRuntimeConfig(old)
				writeError(w, 500, e.Error())
				return
			}
		}
		writeJSON(w, 200, p)
		return
	default:
		writeError(w, 400, "Unknown profile action")
		return
	}
	if e = writeProfiles(p); e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, p)
}
