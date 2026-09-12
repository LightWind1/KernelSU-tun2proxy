// Certificate compatibility layer inspired by MoveCertificate (Apache-2.0).
// New implementation: owned generation mounts, immutable baseline, explicit verification.
// Never modifies the underlying system/APEX or user trust store.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"tun2proxy-web/certificate"
)

var certStore = certificate.Store{Dir: "/data/adb/tun2proxy/certificates"}

type TrustEnvironment struct {
	SDK        int      `json:"sdk"`
	Release    string   `json:"androidVersion"`
	KSU        string   `json:"kernelSU"`
	Targets    []string `json:"targets"`
	Namespaces []int    `json:"namespaces"`
	GM         string   `json:"gmSupport"`
}
type CertMount struct {
	PID    int               `json:"pid"`
	NS     string            `json:"namespace"`
	Target string            `json:"target"`
	Source string            `json:"source"`
	Files  map[string]string `json:"files"`
}
type MountState struct {
	Boot   string      `json:"boot"`
	Mounts []CertMount `json:"mounts"`
}

func certCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return string(out), fmt.Errorf("%s failed: %s", name, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
func certLocked(fn func() error) error {
	if e := os.MkdirAll(certStore.Dir, 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(certStore.Dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func detectTrust() (TrustEnvironment, error) {
	d := TrustEnvironment{GM: "unknown", Targets: []string{}, Namespaces: []int{}}
	sdk, _ := certCommand("getprop", "ro.build.version.sdk")
	d.SDK, _ = strconv.Atoi(sdk)
	d.Release, _ = certCommand("getprop", "ro.build.version.release")
	d.KSU, _ = certCommand("/data/adb/ksud", "-V")
	if d.SDK < 24 {
		return d, errors.New("Android SDK below 24 or unavailable")
	}
	target := "/system/etc/security/cacerts"
	if d.SDK >= 34 {
		target = "/apex/com.android.conscrypt/cacerts"
	}
	st, e := os.Stat(target)
	if e != nil || !st.IsDir() {
		return d, errors.New("active Android trust store unavailable")
	}
	d.Targets = append(d.Targets, target)
	if d.SDK >= 34 {
		parent, err := os.Stat(filepath.Dir(target))
		if err != nil {
			return d, err
		}
		dirs, _ := filepath.Glob("/apex/com.android.conscrypt@*/cacerts")
		for _, p := range dirs {
			if s, e := os.Stat(filepath.Dir(p)); e == nil && os.SameFile(parent, s) {
				d.Targets = append(d.Targets, p)
			}
		}
		if len(d.Targets) < 2 {
			return d, errors.New("cannot resolve active versioned Conscrypt APEX")
		}
	}
	pids := []int{1, os.Getpid()}
	for _, name := range []string{"zygote", "zygote64"} {
		out, _ := certCommand("pidof", name)
		for _, v := range strings.Fields(out) {
			p, _ := strconv.Atoi(v)
			if p > 0 {
				pids = append(pids, p)
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range pids {
		ns, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", p))
		if e == nil && !seen[ns] {
			seen[ns] = true
			d.Namespaces = append(d.Namespaces, p)
		}
	}
	return d, nil
}
func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}
func mountState() (MountState, error) {
	s := MountState{Boot: bootID()}
	b, e := os.ReadFile(filepath.Join(certStore.Dir, "mounts.json"))
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, e
	}
	if s.Boot != bootID() {
		return MountState{Boot: bootID()}, nil
	}
	return s, nil
}
func saveMounts(s MountState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return certificate.Atomic(filepath.Join(certStore.Dir, "mounts.json"), b)
}
func nsCommand(pid int, args ...string) (string, error) {
	return certCommand("nsenter", append([]string{fmt.Sprintf("--mount=/proc/%d/ns/mnt", pid), "--"}, args...)...)
}
func namespacePath(pid int, p string) string { return fmt.Sprintf("/proc/%d/root%s", pid, p) }
func mountRoot(pid int, target string) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	root := ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 5 && f[4] == target {
			root = f[3]
		}
	}
	runtime := filepath.Join(certStore.Dir, "runtime")
	diskRoot := filesystemRoot(runtime)
	if strings.HasPrefix(root, diskRoot+"/") {
		return runtime + strings.TrimPrefix(root, diskRoot)
	}
	return root
}
func filesystemRoot(path string) string {
	b, _ := os.ReadFile("/proc/self/mountinfo")
	best := ""
	root := ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 5 && (path == f[4] || strings.HasPrefix(path, strings.TrimSuffix(f[4], "/")+"/")) && len(f[4]) > len(best) {
			best = f[4]
			root = f[3]
		}
	}
	if best == "" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, best))
}
func ownedRoot(root string) bool { return strings.HasPrefix(root, certStore.Dir+"/runtime/") }
func regularPublic(path string) (certificate.Certificate, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return certificate.Certificate{}, e
	}
	if !s.Mode().IsRegular() || s.Size() > certificate.MaxSize {
		return certificate.Certificate{}, errors.New("unsafe certificate file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return certificate.Certificate{}, e
	}
	return certificate.Parse(b)
}
func copyDirectory(src, dst string) error {
	entries, e := os.ReadDir(src)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(dst, 0700); e != nil {
		return e
	}
	for _, ent := range entries {
		if ent.Type()&os.ModeSymlink != 0 || ent.IsDir() {
			return errors.New("unexpected trust store entry")
		}
		b, e := os.ReadFile(filepath.Join(src, ent.Name()))
		if e != nil {
			return e
		}
		if len(b) > certificate.MaxSize {
			return errors.New("oversized trust store entry")
		}
		if e = os.WriteFile(filepath.Join(dst, ent.Name()), b, 0644); e != nil {
			return e
		}
	}
	return nil
}

// Plan prepares complete baseline+managed generations without touching live stores.
func planTrust(v certificate.Inventory, d TrustEnvironment, previous MountState) ([]CertMount, error) {
	count := 0
	for _, e := range v.Entries {
		if e.Managed {
			count++
		}
	}
	if count == 0 {
		return nil, nil
	}
	plans := []CertMount{}
	prepared := map[string]CertMount{}
	for _, pid := range d.Namespaces {
		for _, target := range d.Targets {
			root := mountRoot(pid, target)
			info, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
			layers := 0
			for _, line := range strings.Split(string(info), "\n") {
				f := strings.Fields(line)
				if len(f) > 5 && f[4] == target {
					layers++
				}
			}
			if layers >= 32 {
				return nil, errors.New("CA mount generation limit reached; reboot before applying again")
			}
			if root != "" && !ownedRoot(root) {
				return nil, fmt.Errorf("foreign CA mount at %s; disable the other certificate module and reboot first", target)
			}
			if ready, ok := prepared[target]; ok {
				ready.PID = pid
				ready.NS, _ = os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
				plans = append(plans, ready)
				continue
			}
			base := namespacePath(pid, target)
			// Previous generation contains a separate immutable baseline.
			if ownedRoot(root) {
				base = filepath.Join(filepath.Dir(root), "base")
			}
			dir, e := os.MkdirTemp(filepath.Join(certStore.Dir, "runtime"), "gen-")
			if e != nil {
				return nil, e
			}
			baseline := filepath.Join(dir, "base")
			live := filepath.Join(dir, "live")
			if e = copyDirectory(base, baseline); e != nil {
				return nil, e
			}
			if e = copyDirectory(baseline, live); e != nil {
				return nil, e
			}
			names := map[string]string{}
			entries, _ := os.ReadDir(live)
			for _, entry := range entries {
				c, e := regularPublic(filepath.Join(live, entry.Name()))
				if e == nil {
					names[entry.Name()] = c.ID
				} else {
					names[entry.Name()] = "reserved"
				}
			}
			files := map[string]string{}
			for _, entry := range certificate.Entries(v) {
				if !entry.Managed {
					continue
				}
				c, e := certStore.Read(entry.ID)
				if e != nil {
					return nil, e
				}
				if c.Type == "gm" && !probeAndroid(c.ID).SignatureValid {
					return nil, errors.New("Android cannot verify this GM CA signature")
				}
				name, _ := certificate.AllocateName(c, names)
				names[name] = c.ID
				files[c.ID] = name
				if e = os.WriteFile(filepath.Join(live, name), c.PEM(), 0644); e != nil {
					return nil, e
				}
			}
			// Mirror the actual target context. Do not use broad chmod on user directories.
			out, e := certCommand("ls", "-Zd", namespacePath(pid, target))
			if e != nil {
				return nil, e
			}
			fields := strings.Fields(out)
			if len(fields) == 0 || !strings.Contains(fields[0], ":object_r:") {
				return nil, errors.New("cannot determine CA SELinux context")
			}
			if _, e = certCommand("chcon", "-R", fields[0], live); e != nil {
				return nil, e
			}
			if e = os.Chmod(live, 0755); e != nil {
				return nil, e
			}
			ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
			m := CertMount{pid, ns, target, live, files}
			prepared[target] = m
			plans = append(plans, m)
		}
	}
	return plans, nil
}
func verifyMount(m CertMount) error {
	ns, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", m.PID))
	if e != nil || ns != m.NS {
		return errors.New("mount namespace changed")
	}
	if mountRoot(m.PID, m.Target) != m.Source {
		return errors.New("owned mount not visible in target namespace")
	}
	for id, name := range m.Files {
		if filepath.Base(name) != name {
			return errors.New("invalid mount filename")
		}
		c, e := regularPublic(namespacePath(m.PID, filepath.Join(m.Target, name)))
		if e != nil || c.ID != id {
			return errors.New("mounted fingerprint verification failed")
		}
	}
	return nil
}

// Only pop mounts with our private source prefix, never somebody else's overlay.
func removeTrust() error {
	d, e := detectTrust()
	if e != nil {
		return e
	}
	for _, pid := range d.Namespaces {
		for _, target := range d.Targets {
			for i := 0; ownedRoot(mountRoot(pid, target)); i++ {
				if i >= 64 {
					return errors.New("too many owned mount layers")
				}
				if _, e = nsCommand(pid, "umount", target); e != nil {
					return e
				}
			}
		}
	}
	return saveMounts(MountState{Boot: bootID()})
}
func applyTrust(v certificate.Inventory) error {
	d, e := detectTrust()
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Join(certStore.Dir, "runtime"), 0700); e != nil {
		return e
	}
	old, e := mountState()
	if e != nil {
		return e
	}
	plans, e := planTrust(v, d, old)
	if e != nil {
		return e
	}
	if len(plans) == 0 {
		return removeTrust()
	}
	// Record intent before the first mount; removal uses actual mount ownership.
	next := MountState{Boot: bootID(), Mounts: plans}
	if e = saveMounts(next); e != nil {
		return e
	}
	rollback := func(cause error) error {
		var recovery error
		for i := len(plans) - 1; i >= 0; i-- {
			m := plans[i]
			if mountRoot(m.PID, m.Target) == m.Source {
				_, err := nsCommand(m.PID, "umount", m.Target)
				recovery = errors.Join(recovery, err)
			}
		}
		if recovery != nil {
			return fmt.Errorf("%w; rollback incomplete (journal retained): %v", cause, recovery)
		}
		return errors.Join(cause, saveMounts(old))
	}
	for _, m := range plans {
		if mountRoot(m.PID, m.Target) == m.Source {
			continue
		}
		if _, e = nsCommand(m.PID, "mount", "--bind", m.Source, m.Target); e != nil {
			return rollback(e)
		}
		if e = verifyMount(m); e != nil {
			return rollback(e)
		}
	}
	for _, m := range plans {
		if e = verifyMount(m); e != nil {
			return rollback(e)
		}
	}
	// AndroidCAStore must expose every managed normal CA in init's namespace.
	for _, entry := range v.Entries {
		if entry.Managed {
			probe := probeAndroid(entry.ID)
			if !probe.Trusted {
				return rollback(errors.New("AndroidCAStore verification failed: " + probe.Error))
			}
		}
	}
	return nil
}

type AndroidProbe struct {
	Parsed         bool   `json:"parsed"`
	SignatureValid bool   `json:"signatureValid"`
	Trusted        bool   `json:"trusted"`
	Provider       string `json:"provider"`
	Error          string `json:"error,omitempty"`
}

func probeAndroid(id string) AndroidProbe {
	p, e := certStore.Path(id)
	if e != nil {
		return AndroidProbe{Error: e.Error()}
	}
	out, e := nsCommand(1, "env", "CLASSPATH="+filepath.Join(modDir, "system", "framework", "certificate-probe.jar"), "app_process", "/system/bin", "CertificateProbe", p)
	var result AndroidProbe
	if e != nil {
		return AndroidProbe{Error: "Android certificate probe unavailable"}
	}
	if json.Unmarshal([]byte(out), &result) != nil {
		return AndroidProbe{Error: "Android certificate probe returned invalid JSON"}
	}
	return result
}
func certBootCLI() bool {
	if len(os.Args) != 2 || (os.Args[1] != "--cert-apply" && os.Args[1] != "--cert-remove") {
		return false
	}
	e := certLocked(func() error {
		if os.Args[1] == "--cert-remove" {
			return removeTrust()
		}
		v, e := certStore.Load()
		if e != nil {
			return e
		}
		return applyTrust(v)
	})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	return true
}
