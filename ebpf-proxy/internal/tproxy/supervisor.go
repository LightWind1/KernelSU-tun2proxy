package tproxy

import (
	"fmt"
	"time"
)

// Retry budgets never reset during a run; healthy operation does not grant
// unlimited future restarts. Bounds are intentionally small for this PoC.
type SupervisorOptions struct {
	MaxRestarts     int
	ReadyTimeout    time.Duration
	StopGrace       time.Duration
	KillWait        time.Duration
	RecoveryTimeout time.Duration
	Backoff         time.Duration
}

func (o SupervisorOptions) Validate() error {
	if o.MaxRestarts < 0 || o.MaxRestarts > 3 || o.ReadyTimeout < 10*time.Millisecond || o.ReadyTimeout > 30*time.Second || o.StopGrace < 10*time.Millisecond || o.StopGrace > 10*time.Second || o.KillWait < 10*time.Millisecond || o.KillWait > 5*time.Second || o.RecoveryTimeout < time.Second || o.RecoveryTimeout > 120*time.Second || o.Backoff < 10*time.Millisecond || o.Backoff > time.Second {
		return fmt.Errorf("invalid bounded supervisor options")
	}
	return nil
}

type SupervisedAttempt struct {
	Number         int    `json:"number"`
	Ready          bool   `json:"ready"`
	Reason         string `json:"reason"`
	ExitObserved   bool   `json:"exit_observed"`
	ExitCode       int    `json:"exit_code"`
	TermRequested  bool   `json:"term_requested"`
	KillRequested  bool   `json:"kill_requested"`
	Clean          bool   `json:"clean"`
	RecoveredSteps int    `json:"recovered_steps"`
}

type SupervisorResult struct {
	Version  int                 `json:"version"`
	State    string              `json:"state"`
	Clean    bool                `json:"clean"`
	Restarts int                 `json:"restarts"`
	Attempts []SupervisedAttempt `json:"attempts"`
}
