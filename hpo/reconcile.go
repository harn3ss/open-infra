package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// reconcile advances one TuningJob: build the grid on first sight, launch trials up to
// maxParallel, collect each finished trial's metric, and — once every trial is terminal —
// pick the best and finish. Idempotent: safe to call every poll.
func (c *controller) reconcile(ctx context.Context, tj TuningJob) {
	ns, name := tj.Metadata.Namespace, tj.Metadata.Name
	if tj.Status.Phase == "Succeeded" || tj.Status.Phase == "Failed" {
		return
	}

	trials := tj.Status.Trials
	if len(trials) == 0 {
		combos := gridTrials(tj.Spec.Parameters, tj.Spec.MaxTrials)
		for i, combo := range combos {
			trials = append(trials, Trial{Name: fmt.Sprintf("%s-t%d", name, i+1), Parameters: combo, Status: "Pending"})
		}
		if len(trials) == 0 {
			_ = c.client.patchTuningStatus(ctx, ns, name, map[string]any{"phase": "Failed"})
			return
		}
		_ = c.client.patchTuningStatus(ctx, ns, name, map[string]any{
			"phase": "Running", "trials": trials, "trialsTotal": len(trials), "trialsComplete": 0,
		})
		log.Printf("tuningjob %s/%s: %d trials", ns, name, len(trials))
	}

	maxPar := tj.Spec.MaxParallel
	if maxPar < 1 {
		maxPar = 1
	}
	goal := tj.Spec.Objective.Goal
	if goal == "" {
		goal = "Minimize"
	}

	running := 0
	for i := range trials {
		if trials[i].Status == "Running" {
			running++
		}
	}

	changed := false
	for i := range trials {
		t := &trials[i]
		switch t.Status {
		case "Pending":
			if running >= maxPar {
				continue
			}
			if err := c.client.createTrainingJob(ctx, ns, c.buildTrial(tj, *t)); err != nil {
				log.Printf("tuningjob %s/%s: create trial %s: %v", ns, name, t.Name, err)
				continue
			}
			t.Status = "Running"
			running++
			changed = true
			log.Printf("tuningjob %s/%s: launched trial %s %v", ns, name, t.Name, t.Parameters)
		case "Running":
			js, found, err := c.client.getJobStatus(ctx, ns, t.Name+"-train")
			if err != nil || !found {
				continue
			}
			if js.succeeded() {
				if logs, err := c.client.trialLogs(ctx, ns, t.Name); err == nil {
					if v, ok := extractMetric(logs, tj.Spec.MetricRegex); ok {
						t.Metric = v
					}
				}
				t.Status = "Succeeded"
				running--
				changed = true
				log.Printf("tuningjob %s/%s: trial %s succeeded metric=%s", ns, name, t.Name, t.Metric)
			} else if js.failed() {
				t.Status = "Failed"
				running--
				changed = true
				log.Printf("tuningjob %s/%s: trial %s failed", ns, name, t.Name)
			}
		}
	}

	complete := 0
	for _, t := range trials {
		if t.Status == "Succeeded" || t.Status == "Failed" {
			complete++
		}
	}

	status := map[string]any{"phase": "Running", "trials": trials, "trialsTotal": len(trials), "trialsComplete": complete}
	if complete == len(trials) {
		var bestT *Trial
		best := ""
		for i := range trials {
			t := &trials[i]
			if t.Status != "Succeeded" || t.Metric == "" {
				continue
			}
			if bestT == nil || better(t.Metric, best, goal) {
				bestT, best = t, t.Metric
			}
		}
		if bestT != nil {
			pj, _ := json.Marshal(bestT.Parameters)
			status["phase"] = "Succeeded"
			status["bestTrial"] = bestT.Name
			status["bestValue"] = bestT.Metric
			status["bestParameters"] = string(pj)
			log.Printf("tuningjob %s/%s: DONE best=%s value=%s params=%s", ns, name, bestT.Name, bestT.Metric, string(pj))
		} else {
			status["phase"] = "Failed"
			log.Printf("tuningjob %s/%s: DONE but no trial produced a metric", ns, name)
		}
	}
	if changed || complete == len(trials) {
		if err := c.client.patchTuningStatus(ctx, ns, name, status); err != nil {
			log.Printf("tuningjob %s/%s: patch status: %v", ns, name, err)
		}
	}
}

// buildTrial constructs a TrainingJob claim for one trial: the base training spec, plus
// the trial's hyperparameters as env, a per-trial output prefix, and an ownerReference so
// deleting the TuningJob garbage-collects the trials.
func (c *controller) buildTrial(tj TuningJob, t Trial) map[string]any {
	spec := map[string]any{}
	for k, v := range tj.Spec.Training {
		spec[k] = v
	}
	// env = base env + trial hyperparameters
	env := []any{}
	if e, ok := tj.Spec.Training["env"].([]any); ok {
		env = append(env, e...)
	}
	for k, v := range t.Parameters {
		env = append(env, map[string]any{"name": k, "value": v})
	}
	spec["env"] = env
	// per-trial output prefix
	if o, ok := tj.Spec.Training["output"].(map[string]any); ok {
		base, _ := o["prefix"].(string)
		no := map[string]any{}
		for k, v := range o {
			no[k] = v
		}
		no["prefix"] = strings.TrimRight(base, "/") + "/" + t.Name + "/"
		spec["output"] = no
	}
	return map[string]any{
		"apiVersion": "openinfra.dev/v1",
		"kind":       "TrainingJob",
		"metadata": map[string]any{
			"name":      t.Name,
			"namespace": tj.Metadata.Namespace,
			"labels":    map[string]any{"openinfra.dev/tuningjob": tj.Metadata.Name},
			"ownerReferences": []any{map[string]any{
				"apiVersion":         "openinfra.dev/v1",
				"kind":               "TuningJob",
				"name":               tj.Metadata.Name,
				"uid":                tj.Metadata.UID,
				"controller":         true,
				"blockOwnerDeletion": false,
			}},
		},
		"spec": spec,
	}
}
