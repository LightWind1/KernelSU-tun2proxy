package tproxy

import (
	"testing"
	"time"
)

func supervisorOptions() SupervisorOptions {
	return SupervisorOptions{MaxRestarts: 1, ReadyTimeout: 8 * time.Second, StopGrace: 8 * time.Second, KillWait: 2 * time.Second, RecoveryTimeout: 20 * time.Second, Backoff: 20 * time.Millisecond}
}

func TestSupervisorBounds(t *testing.T) {
	if e := supervisorOptions().Validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*SupervisorOptions){func(o *SupervisorOptions) { o.MaxRestarts = -1 }, func(o *SupervisorOptions) { o.MaxRestarts = 4 }, func(o *SupervisorOptions) { o.ReadyTimeout = 0 }, func(o *SupervisorOptions) { o.ReadyTimeout = time.Minute }, func(o *SupervisorOptions) { o.StopGrace = 11 * time.Second }, func(o *SupervisorOptions) { o.KillWait = 6 * time.Second }, func(o *SupervisorOptions) { o.RecoveryTimeout = 121 * time.Second }, func(o *SupervisorOptions) { o.Backoff = 2 * time.Second }} {
		o := supervisorOptions()
		change(&o)
		if o.Validate() == nil {
			t.Fatal("unbounded policy accepted")
		}
	}
}
