package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/lib/pq"
)

// A backing Postgres the shim started without (unreachable at start) leaves the services it holds
// unconfigured: they answer "not configured" while the rest of the shim serves. The stores are built once,
// at start, so the way back is a restart. restartWhenReachable makes that restart happen: it pings the
// database until it answers, then restarts the shim, whose start then connects. Without it the services
// stayed down until someone restarted the pod — a node event once restarted the shim minutes before its
// Postgres, and Route 53 Resolver (with SQS, SNS, KMS and the rest) stayed unconfigured for hours, so VPC
// functions resolved no name.

// errPGUnreachable marks a start that failed because the Postgres did not answer (the case a restart, once
// it answers, fixes), not because its schema could not be set up.
var errPGUnreachable = errors.New("the Postgres is unreachable")

// pgUnreachable reports whether a start failed because the Postgres did not answer, so a restart once it
// answers fixes it. That is a failed ping (errPGUnreachable), and also a connection lost after the ping, while
// the schema was being set up: a Postgres that is shutting down (its node drained) answers the ping and then
// refuses the next connection. Without this, that start was taken for a schema error and the services stayed
// unconfigured until someone restarted the shim. An error the database returns about the schema itself (a
// permission, a syntax error) is not unreachability.
func pgUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errPGUnreachable) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var pe *pq.Error
	if errors.As(err, &pe) {
		switch pe.Code.Class() {
		case "08", "57": // connection exception; operator intervention (shutdown, cannot connect now)
			return true
		}
	}
	return false
}

// pgRecoverEvery is how often an unreachable backing Postgres is tried again.
const pgRecoverEvery = 15 * time.Second

// pgPing opens dsn and pings it, closing what it opened.
func pgPing(dsn string) func(context.Context) error {
	return func(ctx context.Context) error {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.PingContext(ctx)
	}
}

// restartWhenReachable tries ping every interval until it succeeds, then calls restart once; it returns
// when ctx ends first.
func restartWhenReachable(ctx context.Context, what string, ping func(context.Context) error, every time.Duration,
	logger *slog.Logger, restart func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := ping(pctx)
		cancel()
		if err == nil {
			if logger != nil {
				logger.Warn("backing Postgres reachable again; restarting the shim so the services it holds come up",
					slog.String("store", what))
			}
			restart()
			return
		}
	}
}

// restartSelf asks this process to shut down gracefully (SIGTERM, as Kubernetes does); the container then
// restarts it.
func restartSelf() { _ = syscall.Kill(os.Getpid(), syscall.SIGTERM) }
