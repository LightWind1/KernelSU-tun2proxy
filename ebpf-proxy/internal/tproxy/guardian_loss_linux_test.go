//go:build linux

package tproxy

import (
	"bufio"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureStartTime(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	end := strings.LastIndex(string(b), ")")
	if end < 0 {
		return "", fmt.Errorf("invalid stat")
	}
	f := strings.Fields(string(b)[end+1:])
	if len(f) <= 19 {
		return "", fmt.Errorf("short stat")
	}
	return f[19], nil
}

func TestLostGuardianWorker(t *testing.T) {
	dir := os.Getenv("TP_LOST_GUARDIAN_DIR")
	if dir == "" {
		t.Skip("fixture guardian only")
	}
	c, cancel := pendingWorker(t, dir, "add", "", 8)
	defer cancel()
	start, e := fixtureStartTime(c.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("GUARDIAN_READY %d %s\n", c.Process.Pid, start)
	if _, e := WatchIsolatedWorker(c, dir, journalPlan()); e != nil {
		t.Fatal(e)
	}
}

func TestPrivilegedGuardianLoss(t *testing.T) {
	if !privateRecoveryChild(t, "TP_GUARDIAN_LOSS_CHILD", "TestPrivilegedGuardianLoss") {
		return
	}
	// Probe without spawning an orphan first. Missing pidfd support must not
	// leave a paused worker alive in an otherwise abandoned namespace.
	probeFD, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		t.Skipf("pidfd_open unavailable: %v", e)
	}
	e = unix.PidfdSendSignal(probeFD, 0, nil, 0)
	unix.Close(probeFD)
	if e != nil {
		t.Skipf("pidfd signal capability unavailable: %v", e)
	}
	dir := privateJournalTestDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLostGuardianWorker$", "-test.v")
	c.Env = append(os.Environ(), "TP_LOST_GUARDIAN_DIR="+dir)
	pipe, e := c.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	c.Stderr = c.Stdout
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	var header []string
	var output []string
	scan := bufio.NewScanner(pipe)
	for scan.Scan() {
		output = append(output, scan.Text())
		if strings.HasPrefix(scan.Text(), "GUARDIAN_READY ") {
			header = strings.Fields(scan.Text())
			break
		}
	}
	if len(header) != 3 {
		// Keep the original guardian alive while its bounded child context
		// terminates/cleans the fixture. Killing it first could orphan a worker.
		c.Wait()
		t.Fatal("guardian not ready", output)
	}
	pid, e := strconv.Atoi(header[1])
	if e != nil {
		t.Fatal(e)
	}
	fd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		c.Wait()
		t.Fatalf("pidfd_open unavailable: %v", e)
	}
	defer unix.Close(fd)
	start, e := fixtureStartTime(pid)
	if e != nil || start != header[2] {
		c.Wait()
		t.Fatal("worker identity changed", e)
	}
	// Only the kernel-pinned verified test process can be signalled here.
	defer unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
	before, e := isolatedSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = c.Wait(); e == nil {
		t.Fatal("guardian not killed")
	}
	after, e := isolatedSnapshot()
	if e != nil || after != before {
		t.Fatal("guardian kill changed resources", e)
	}
	if d, e := OpenDurableIsolated(dir, journalPlan()); e == nil {
		d.Close()
		t.Fatal("live orphan ownership stolen")
	}
	// Cancellation must not delete rules while the orphan is still alive.
	probe, cancelProbe := context.WithTimeout(context.Background(), 150*time.Millisecond)
	if _, e = WatchIsolatedPIDFD(probe, fd, dir, journalPlan()); e == nil {
		t.Fatal("recovered live worker")
	}
	cancelProbe()
	after, e = isolatedSnapshot()
	if e != nil || after != before {
		t.Fatal("cancelled observer mutated resources", e)
	}
	ordinary, e := os.Open("/proc/self/stat")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = WatchIsolatedPIDFD(ctx, int(ordinary.Fd()), dir, journalPlan()); e == nil {
		t.Fatal("ordinary file admitted as pidfd")
	}
	ordinary.Close()
	if e = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); e != nil {
		t.Fatal(e)
	}
	r, e := WatchIsolatedPIDFD(ctx, fd, dir, journalPlan())
	if e != nil || !r.Clean || !r.ExitObserved || r.ExitCodeKnown || r.RecoveredSteps != 8 {
		t.Fatalf("replacement guardian: %+v %v", r, e)
	}
	d, e := OpenDurableIsolated(dir, journalPlan())
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Recover(); e != nil {
		t.Fatal(e)
	}
	d.Close()
	t.Log("guardian SIGKILL: orphan remains locked; pidfd identity pinned; no premature cleanup; replacement recovers 8 steps after orphan exit")
}
