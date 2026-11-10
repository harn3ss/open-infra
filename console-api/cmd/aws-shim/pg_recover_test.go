package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// A shim that started without its Postgres restarts once the Postgres answers, and only then: the
// services it holds come up without anyone restarting the pod.
func TestRestartWhenReachable_RestartsOnceThePostgresAnswers(t *testing.T) {
	var pings, restarts atomic.Int32
	ping := func(context.Context) error {
		if pings.Add(1) < 3 {
			return errors.New("connection refused")
		}
		return nil
	}
	done := make(chan struct{})
	go func() {
		restartWhenReachable(context.Background(), "shared", ping, time.Millisecond, nil, func() { restarts.Add(1) })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher never restarted the shim")
	}
	if pings.Load() != 3 || restarts.Load() != 1 {
		t.Errorf("pings %d, restarts %d: want a restart once, on the first answer", pings.Load(), restarts.Load())
	}
}

// While the Postgres stays down nothing restarts, and the watcher ends with the shim.
func TestRestartWhenReachable_NothingWhileItIsDown(t *testing.T) {
	var restarts atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		restartWhenReachable(ctx, "shared", func(context.Context) error { return errors.New("down") }, time.Millisecond, nil,
			func() { restarts.Add(1) })
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not end with the shim")
	}
	if restarts.Load() != 0 {
		t.Errorf("restarted %d times while the Postgres was down", restarts.Load())
	}
}

// Only an unreachable Postgres is watched: a schema error is not something a restart fixes.
func TestErrPGUnreachable_MarksOnlyUnreachability(t *testing.T) {
	unreachable := fmt.Errorf("SQS_PG_URI set but the SQS Postgres is unreachable: %w (%w)", errors.New("dial tcp: refused"), errPGUnreachable)
	if !errors.Is(unreachable, errPGUnreachable) {
		t.Error("an unreachable Postgres must be marked")
	}
	if errors.Is(fmt.Errorf("SQS schema init failed: %w", errors.New("permission denied")), errPGUnreachable) {
		t.Error("a schema error must not be marked")
	}
}
