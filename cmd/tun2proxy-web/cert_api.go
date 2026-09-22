package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"
	"tun2proxy-web/certificate"
	"tun2proxy-web/yakit"
)

type LocalCA struct {
	certificate.Certificate
	Source string `json:"source"`
	User   string `json:"user,omitempty"`
	path   string
}

// Injectable at the transaction boundary for failure/rollback tests.
var certificateApply = applyTrust

func localCAs(source string) ([]LocalCA, error) {
	dirs := []string{}
	if source == "user" {
		dirs, _ = filepath.Glob("/data/misc/user/*/cacerts-added")
	} else if source == "system" {
		d, e := detectTrust()
		if e != nil {
			return nil, e
		}
		dirs = []string{d.Targets[0]}
		// Never report an injected CA as an original factory CA.
		if root := mountRoot(os.Getpid(), dirs[0]); ownedRoot(root) {
			dirs = []string{filepath.Join(filepath.Dir(root), "base")}
		}
	} else {
		return nil, errors.New("invalid local certificate source")
	}
	out := []LocalCA{}
	for _, dir := range dirs {
		entries, e := os.ReadDir(dir)
		if e != nil {
			if os.IsNotExist(e) {
				continue
			}
			return nil, e
		}
		for _, f := range entries {
			if f.IsDir() || f.Type()&os.ModeSymlink != 0 {
				continue
			}
			p := filepath.Join(dir, f.Name())
			c, e := regularPublic(p)
			if e != nil {
				continue
			}
			user := ""
			if source == "user" {
				user = filepath.Base(filepath.Dir(dir))
			}
			out = append(out, LocalCA{Certificate: c, Source: source, User: user, path: p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}
func resolveUser(id, user string) (LocalCA, error) {
	if !certificate.ValidID(id) {
		return LocalCA{}, errors.New("invalid certificate ID")
	}
	list, e := localCAs("user")
	if e != nil {
		return LocalCA{}, e
	}
	for _, c := range list {
		if c.ID == id && c.User == user {
			return c, nil
		}
	}
	return LocalCA{}, errors.New("user certificate not found")
}
func certAudit(op, id, source string, err error) {
	os.MkdirAll(logDir, 0755)
	f, e := os.OpenFile(filepath.Join(logDir, "certificate.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	sdk, _ := certCommand("getprop", "ro.build.version.sdk")
	result := "ok"
	if err != nil {
		result = err.Error()
	}
	d, _ := detectTrust()
	mountResult := "not-requested"
	verifyResult := "not-requested"
	if op == "install" || op == "remove" || op == "apply" {
		mountResult = result
		verifyResult = result
	}
	if source == "" {
		if v, e := certStore.Load(); e == nil {
			source = v.Entries[id].Source
		}
	}
	_ = json.NewEncoder(f).Encode(map[string]interface{}{"time": time.Now().UTC().Format(time.RFC3339), "operation": op, "certificateID": id, "sha256": id, "source": source, "sdk": sdk, "targetTrustStores": d.Targets, "mountResult": mountResult, "verifyResult": verifyResult, "result": result})
}
func certHTTP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil || !net.ParseIP(host).IsLoopback() {
			writeError(w, 403, "Certificate administration is local-only; open on the phone or via ADB forwarding")
			return
		}
		requestHost, _, e := net.SplitHostPort(r.Host)
		if e != nil || (requestHost != "localhost" && !net.ParseIP(requestHost).IsLoopback()) {
			writeError(w, 403, "Invalid certificate API host")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || u.Scheme != "http" || u.Host != r.Host {
				writeError(w, 403, "Cross-origin certificate action denied")
				return
			}
		}
		if r.Header.Get("X-Tun2proxy-Certificate") != "1" {
			writeError(w, 403, "Missing certificate action header")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, certificate.MaxSize+4096)
		next(w, r)
	}
}
func certificateView(v certificate.Inventory) map[string]interface{} {
	mounts, me := mountState()
	d, de := detectTrust()
	mounted := map[string]bool{}
	valid := me == nil && len(mounts.Mounts) > 0
	for _, m := range mounts.Mounts {
		if verifyMount(m) != nil {
			valid = false
		}
	}
	if valid {
		for _, m := range mounts.Mounts {
			for id := range m.Files {
				mounted[id] = true
			}
		}
	}
	users, ue := localCAs("user")
	stock, se := localCAs("system")
	pending := 0
	for _, e := range v.Entries {
		if e.Managed && !mounted[e.ID] {
			pending++
		}
	}
	capabilities := map[string]AndroidProbe{}
	for id, e := range v.Entries {
		if e.Type == "gm" {
			capabilities[id] = probeAndroid(id)
		}
	}
	errs := []string{}
	for _, e := range []error{me, de, ue, se} {
		if e != nil {
			errs = append(errs, e.Error())
		}
	}
	return map[string]interface{}{"entries": certificate.Entries(v), "yakit": v.Yakit, "users": users, "system": stock, "environment": d, "mounted": mounted, "pending": pending, "mounts": mounts.Mounts, "capabilities": capabilities, "errors": errs}
}
func endpointKey(proxyURL string) (string, error) {
	u, e := url.Parse(proxyURL)
	if e != nil || u.Scheme != "http" || u.Hostname() == "" || u.Port() == "" {
		return "", errors.New("Yakit certificates require a saved HTTP proxy endpoint")
	}
	return "http://" + u.Host, nil
}
func selectedCertProfile(id string) (ConnectionProfile, error) {
	p, e := readProfiles()
	if e != nil {
		return ConnectionProfile{}, e
	}
	if id == "" {
		id = p.ActiveID
	}
	v, ok := profileByID(p, id)
	if !ok {
		return v, errors.New("connection profile not found")
	}
	return v, nil
}
func scopedYakit(v *certificate.Inventory, key string) bool {
	if active, e := selectedCertProfile(""); e == nil {
		if original, e := endpointKey(active.Config.ProxyURL); e == nil {
			key = original
		}
	}
	changed := false
	for _, kind := range []string{"normal", "gm"} {
		old, ok := v.Yakit[kind]
		if !ok {
			continue
		}
		scoped := key + "|" + kind
		if _, exists := v.Yakit[scoped]; !exists {
			if old.LocalID != "" && len(old.History) == 0 {
				old.History = []string{old.LocalID}
			}
			v.Yakit[scoped] = old
		}
		delete(v.Yakit, kind)
		changed = true
	}
	return changed
}
func certList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "Use GET")
		return
	}
	profile, e := selectedCertProfile(r.URL.Query().Get("profile_id"))
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	key, _ := endpointKey(profile.Config.ProxyURL)
	var view map[string]interface{}
	e = certLocked(func() error {
		v, e := certStore.Load()
		if e != nil {
			return e
		}
		if key != "" && scopedYakit(&v, key) {
			if e = certStore.Save(v); e != nil {
				return e
			}
		}
		view = certificateView(v)
		view["profileId"] = profile.ID
		view["profileName"] = profile.Name
		view["proxyEndpoint"] = key
		view["yakit"] = map[string]certificate.Remote{"normal": v.Yakit[key+"|normal"], "gm": v.Yakit[key+"|gm"]}
		return nil
	})
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, view)
}

type CertAction struct {
	Action  string `json:"action"`
	ID      string `json:"id"`
	Source  string `json:"source"`
	User    string `json:"user"`
	Confirm string `json:"confirm"`
}

func certAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "Use POST")
		return
	}
	var a CertAction
	if e := json.NewDecoder(r.Body).Decode(&a); e != nil {
		writeError(w, 400, "Invalid action")
		return
	}
	if !certificate.ValidID(a.ID) && a.Action != "apply" {
		writeError(w, 400, "Invalid certificate ID")
		return
	}
	var result interface{} = map[string]bool{"ok": true}
	e := certLocked(func() error {
		v, e := certStore.Load()
		if e != nil {
			return e
		}
		old, e := certStore.Load()
		if e != nil {
			return e
		}
		switch a.Action {
		case "inspect":
			if a.Source == "user" {
				c, e := resolveUser(a.ID, a.User)
				if e != nil {
					return e
				}
				result = c
				return nil
			}
			if a.Source == "system" {
				list, e := localCAs("system")
				if e != nil {
					return e
				}
				for _, c := range list {
					if c.ID == a.ID {
						result = c
						return nil
					}
				}
				return errors.New("stock CA not found")
			}
			c, e := certStore.Read(a.ID)
			if e != nil {
				return e
			}
			result = map[string]interface{}{"certificate": c, "android": probeAndroid(a.ID)}
			return nil
		case "delete-user":
			if a.Confirm != "DELETE USER "+a.ID {
				return errors.New("explicit user-certificate deletion confirmation required")
			}
			c, e := resolveUser(a.ID, a.User)
			if e != nil {
				return e
			}
			// Private recovery copy before removal; source is re-resolved and fingerprint checked.
			if e = certificate.Atomic(filepath.Join(certStore.Dir, "user-trash", c.User+"-"+c.ID+".pem"), c.PEM()); e != nil {
				return e
			}
			again, e := regularPublic(c.path)
			if e != nil || again.ID != c.ID {
				return errors.New("user CA changed; deletion cancelled")
			}
			return os.Remove(c.path)
		case "delete":
			if a.Confirm != "DELETE CACHE "+a.ID {
				return errors.New("explicit cache deletion confirmation required")
			}
			return certStore.Delete(&v, a.ID)
		case "install":
			if a.Source == "system" {
				return errors.New("stock certificates are read-only")
			}
			if a.Source == "user" {
				c, e := resolveUser(a.ID, a.User)
				if e != nil {
					return e
				}
				if _, e = certStore.Put(&v, c.Certificate, "user"); e != nil {
					return e
				}
			}
			entry, ok := v.Entries[a.ID]
			if !ok {
				return errors.New("managed cache certificate not found")
			}
			c, e := certStore.Read(a.ID)
			if e != nil {
				return e
			}
			if c.Type == "gm" {
				p := probeAndroid(a.ID)
				if !p.Parsed || !p.SignatureValid {
					return errors.New("Android cannot parse/verify this GM CA; export/download remain available")
				}
			}
			if time.Now().Before(c.NotBefore) || time.Now().After(c.NotAfter) {
				return errors.New("CA is not currently valid")
			}
			entry.Managed = true
			entry.UpdatedAt = time.Now().UTC()
			v.Entries[a.ID] = entry
		case "remove":
			entry, ok := v.Entries[a.ID]
			if !ok {
				return errors.New("certificate not managed by this module")
			}
			entry.Managed = false
			entry.UpdatedAt = time.Now().UTC()
			v.Entries[a.ID] = entry
		case "apply":
		default:
			return errors.New("unknown certificate action")
		}
		if e = certificateApply(v); e != nil {
			return e
		}
		if e = certStore.Save(v); e != nil {
			_ = certificateApply(old)
			return e
		}
		return nil
	})
	certAudit(a.Action, a.ID, a.Source, e)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, result)
}
func certImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "Use POST")
		return
	}
	b, e := io.ReadAll(r.Body)
	if e != nil {
		writeError(w, 400, "Upload too large or incomplete")
		return
	}
	c, e := certificate.Parse(b)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	var entry certificate.Entry
	e = certLocked(func() error {
		v, e := certStore.Load()
		if e != nil {
			return e
		}
		entry, e = certStore.Put(&v, c, "import")
		if e != nil {
			return e
		}
		return certStore.Save(v)
	})
	certAudit("import", c.ID, "import", e)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, entry)
}
func certExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "Use GET")
		return
	}
	c, e := certStore.Read(r.URL.Query().Get("id"))
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename="+c.ID+".pem")
	w.Write(c.PEM())
}
func yakitAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "Use POST")
		return
	}
	var request struct {
		Action    string `json:"action"`
		Kind      string `json:"kind"`
		ProfileID string `json:"profile_id"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		writeError(w, 400, "Invalid request")
		return
	}
	if request.Action != "test" && request.Action != "sync" && request.Action != "check" {
		writeError(w, 400, "Unknown Yakit action")
		return
	}
	profile, e := selectedCertProfile(request.ProfileID)
	if e != nil {
		writeError(w, 500, "Cannot read connection configuration")
		return
	}
	key, e := endpointKey(profile.Config.ProxyURL)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	client, e := yakit.New(profile.Config.ProxyURL)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	d, e := client.Discover(r.Context())
	if request.Action == "test" || e != nil || !d.Recognized {
		writeJSON(w, 200, d)
		return
	}
	kinds := []string{"normal", "gm"}
	if request.Kind != "" {
		if request.Kind != "normal" && request.Kind != "gm" {
			writeError(w, 400, "Invalid certificate type")
			return
		}
		kinds = []string{request.Kind}
	}
	results := map[string]interface{}{}
	for _, kind := range kinds {
		c, endpoint, err := client.Download(r.Context(), kind, d)
		if err != nil {
			results[kind] = map[string]string{"error": err.Error()}
			continue
		}
		err = certLocked(func() error {
			v, e := certStore.Load()
			if e != nil {
				return e
			}
			old, e := certStore.Load()
			if e != nil {
				return e
			}
			scopedYakit(&v, key)
			slot := key + "|" + kind
			remote := v.Yakit[slot]
			remote.RemoteID = c.ID
			remote.Endpoint = endpoint
			remote.CheckedAt = time.Now().UTC()
			if request.Action == "sync" {
				entry, e := certStore.Put(&v, c, "yakit-"+kind)
				if e != nil {
					return e
				}
				if prior, ok := v.Entries[remote.LocalID]; ok && prior.Managed && prior.ID != c.ID {
					// New generation is fully verified before committing either fingerprint.
					// A shared CA may still be the current certificate of another computer.
					shared := false
					for other, link := range v.Yakit {
						if other != slot && link.LocalID == prior.ID {
							shared = true
							break
						}
					}
					if !shared {
						prior.Managed = false
						v.Entries[prior.ID] = prior
					}
					entry.Managed = true
					v.Entries[c.ID] = entry
					if e = certificateApply(v); e != nil {
						return e
					}
				}
				remote.LocalID = c.ID
				found := false
				for _, id := range remote.History {
					if id == c.ID {
						found = true
						break
					}
				}
				if !found {
					remote.History = append(remote.History, c.ID)
				}
			}
			v.Yakit[slot] = remote
			if e = certStore.Save(v); e != nil {
				_ = certificateApply(old)
				return e
			}
			results[kind] = remote
			return nil
		})
		certAudit("yakit-"+request.Action, c.ID, "yakit-"+kind, err)
		if err != nil {
			results[kind] = map[string]string{"error": err.Error()}
		}
	}
	writeJSON(w, 200, map[string]interface{}{"discovery": d, "results": results})
}
func registerCertificates(mux *http.ServeMux) {
	mux.HandleFunc("/api/certificates", certHTTP(certList))
	mux.HandleFunc("/api/certificates/action", certHTTP(certAction))
	mux.HandleFunc("/api/certificates/import", certHTTP(certImport))
	mux.HandleFunc("/api/certificates/export", certHTTP(certExport))
	mux.HandleFunc("/api/yakit", certHTTP(yakitAPI))
}
func certificateDiagnostics() string {
	var out string
	e := certLocked(func() error {
		v, e := certStore.Load()
		if e != nil {
			return e
		}
		b, e := json.MarshalIndent(certificateView(v), "", "  ")
		if e != nil {
			return e
		}
		out = string(b)
		return nil
	})
	if e != nil {
		return fmt.Sprint(e)
	}
	return out
}

// No credentials or client-selected filesystem paths are accepted by certificate APIs.
