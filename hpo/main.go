// hpo — open-infra's kind: TuningJob controller (hyperparameter tuning / SageMaker
// Automatic Model Tuning). A single cluster-wide controller watches TuningJob objects,
// runs a kind: TrainingJob per hyperparameter combination (grid search) up to
// maxParallel at a time, reads each trial's reported metric from its logs, and records
// the best trial in status.
//
// Env: POLL_INTERVAL (seconds, default 10).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type controller struct {
	client *k8sClient
}

func main() {
	poll := 10
	if v := os.Getenv("POLL_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			poll = n
		}
	}
	client, err := newInClusterClient()
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	ctrl := &controller{client: client}
	ticker := time.NewTicker(time.Duration(poll) * time.Second)
	defer ticker.Stop()
	log.Printf("tuning controller: watching tuningjobs cluster-wide, polling every %ds", poll)

	reconcileAll := func() {
		tjs, err := ctrl.client.listTuningJobs(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("list tuningjobs: %v", err)
			}
			return
		}
		for _, tj := range tjs {
			ctrl.reconcile(ctx, tj)
		}
	}
	reconcileAll()
	for {
		select {
		case <-ctx.Done():
			log.Printf("tuning controller: shutting down")
			return
		case <-ticker.C:
			reconcileAll()
		}
	}
}
