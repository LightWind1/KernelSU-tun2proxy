package tproxy

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func samplePlan(t *testing.T) []Step {
	t.Helper()
	s, e := (IPv4DestinationPlan{Destination: netip.MustParseAddrPort("198.18.0.1:443"), ListenerPort: 18080, Mark: 1 << 22, Mask: 1 << 22, Table: 38766, Priority: 9001, Prefix: "ATP_TEST"}).Steps()
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestPlanSafety(t *testing.T) {
	s := samplePlan(t)
	if len(s) != 8 || !strings.Contains(strings.Join(s[7].Add, " "), "-I OUTPUT 1") {
		t.Fatal(s)
	}
	for _, step := range s {
		for _, args := range [][]string{step.Add, step.Remove} {
			for _, arg := range args {
				if arg == "-F" || arg == "flush" || arg == "--set-mark" {
					t.Fatal("unsafe operation", args)
				}
			}
		}
	}
	base := IPv4DestinationPlan{Destination: netip.MustParseAddrPort("198.18.0.1:443"), ListenerPort: 18080, Mark: 1 << 22, Mask: 1 << 22, Table: 38766, Priority: 9001, Prefix: "ATP_TEST"}
	for _, mutate := range []func(*IPv4DestinationPlan){
		func(c *IPv4DestinationPlan) { c.Prefix = "../evil" },
		func(c *IPv4DestinationPlan) { c.Prefix = "ATP_X;id" },
		func(c *IPv4DestinationPlan) { c.Table = 254 },
		func(c *IPv4DestinationPlan) { c.Mask = 3 },
		func(c *IPv4DestinationPlan) { c.Mark = 1 },
		func(c *IPv4DestinationPlan) { c.Priority = 0 },
		func(c *IPv4DestinationPlan) { c.ListenerPort = 0 },
		func(c *IPv4DestinationPlan) { c.Destination = netip.MustParseAddrPort("[::1]:443") },
		func(c *IPv4DestinationPlan) { c.Destination = netip.MustParseAddrPort("127.0.0.1:443") },
		func(c *IPv4DestinationPlan) { c.Destination = netip.MustParseAddrPort("255.255.255.255:443") },
	} {
		c := base
		mutate(&c)
		if _, e := c.Steps(); e == nil {
			t.Fatalf("accepted invalid plan %+v", c)
		}
	}
}

func TestTransactionEverySetupFailure(t *testing.T) {
	s := samplePlan(t)
	for failure := 0; failure < len(s); failure++ {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			var calls [][]string
			n := 0
			tx := NewTransaction(s, func(a []string) Result {
				calls = append(calls, a)
				n++
				if n == failure+1 {
					return Result{Command: a, ExitCode: 1, Error: "injected"}
				}
				return Result{Command: a}
			})
			if tx.Setup() == nil || tx.OwnedSteps() != 0 {
				t.Fatal("rollback missing")
			}
			for i := 0; i < failure; i++ {
				if !reflect.DeepEqual(calls[failure+1+i], s[failure-1-i].Remove) {
					t.Fatal(calls)
				}
			}
			if e := tx.Teardown(); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestTransactionFailedDisableRetainedForRetry(t *testing.T) {
	s := samplePlan(t)
	fail := false
	var calls [][]string
	tx := NewTransaction(s, func(a []string) Result {
		calls = append(calls, a)
		if fail {
			return Result{Command: a, ExitCode: 1, Error: "xtables timeout"}
		}
		return Result{Command: a}
	})
	if e := tx.Setup(); e != nil {
		t.Fatal(e)
	}
	fail = true
	if tx.Teardown() == nil || tx.OwnedSteps() != len(s) || len(calls) != len(s)+1 {
		t.Fatal("removed dependency after failed disable")
	}
	if tx.Setup() == nil || len(calls) != len(s)+1 {
		t.Fatal("failed stop must not be reported as ready")
	}
	fail = false
	if e := tx.Teardown(); e != nil {
		t.Fatal(e)
	}
	if tx.OwnedSteps() != 0 {
		t.Fatal("retry lost ownership")
	}
}

func TestTransactionPartialRollbackBlocksSetup(t *testing.T) {
	s := samplePlan(t)
	n := 0
	tx := NewTransaction(s, func(a []string) Result {
		n++
		if n == 3 || n == 4 {
			return Result{Command: a, ExitCode: 1}
		}
		return Result{Command: a}
	})
	if tx.Setup() == nil || tx.OwnedSteps() != 2 {
		t.Fatal("must preserve failed rollback")
	}
	before := n
	if tx.Setup() == nil || n != before {
		t.Fatal("partial rollback must not enable new interception")
	}
	if e := tx.Teardown(); e != nil {
		t.Fatal(e)
	}
}

func TestTransactionIdempotentConcurrentLifecycle(t *testing.T) {
	s := samplePlan(t)
	n := 0
	tx := NewTransaction(s, func(a []string) Result { n++; return Result{Command: a} })
	// Caller mutation cannot change trusted plan retained by the controller.
	s[0].Add[0] = "unsafe"
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := tx.Setup(); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if n != 8 {
		t.Fatal(n)
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := tx.Teardown(); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if n != 16 || tx.OwnedSteps() != 0 {
		t.Fatal(n)
	}
}
