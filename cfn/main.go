// cfn — the open-infra CloudFormation engine (Phase 1).
//
// Phase 1 is read-only: it maps a CloudFormation template onto open-infra kinds and reports
// whether the stack is provisionable, provisionable-with-caveats, or rejected — and exactly
// why. It provisions nothing. Stateful deployment (create/update/delete a real stack) is a
// later phase, deliberately gated behind this dry-run.
//
// Usage:
//
//	cfn plan [-param K=V ...] [-stack-name NAME] [-json] <template.yaml|template.json>
//
// Exit codes:
//
//	0  PROVISIONABLE or PROVISIONABLE_WITH_CAVEATS
//	1  REJECTED (unsupported type/intrinsic, macro, missing param, broken ref, or cycle)
//	2  usage or parse error
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "plan":
		os.Exit(runPlan(os.Args[2:]))
	case "deploy":
		os.Exit(runDeploy(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "cfn: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cfn — open-infra CloudFormation engine

Usage:
  cfn plan   [-param K=V ...] [-stack-name NAME] [-json] <template>
  cfn deploy  -namespace NS -stack-name NAME [-param K=V ...] [-no-wait] [-timeout SECS] <template>

plan   (read-only) reports whether open-infra can provision a template, with caveats, or
       not — and exactly why. Provisions nothing.
deploy (stateful, Phase 2) provisions a stack live, fail-closed: it refuses unless the whole
       template maps and every property translates, applies in dependency order, records the
       stack, and rolls back on failure leaving no orphans.
`)
}

func runPlan(args []string) int {
	params := map[string]string{}
	stackName := ""
	asJSON := false
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-json":
			asJSON = true
		case a == "-param":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "cfn: -param needs K=V")
				return 2
			}
			k, v, ok := strings.Cut(args[i], "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "cfn: bad -param %q (want K=V)\n", args[i])
				return 2
			}
			params[k] = v
		case strings.HasPrefix(a, "-param="):
			k, v, ok := strings.Cut(strings.TrimPrefix(a, "-param="), "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "cfn: bad -param %q (want K=V)\n", a)
				return 2
			}
			params[k] = v
		case a == "-stack-name":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "cfn: -stack-name needs a value")
				return 2
			}
			stackName = args[i]
		case strings.HasPrefix(a, "-stack-name="):
			stackName = strings.TrimPrefix(a, "-stack-name=")
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "cfn: unknown flag %q\n", a)
			return 2
		default:
			files = append(files, a)
		}
	}
	if len(files) != 1 {
		fmt.Fprintln(os.Stderr, "cfn: expected exactly one template file")
		return 2
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 2
	}
	plan, err := BuildPlan(data, params, stackName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 2
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(plan)
	} else {
		printPlan(plan)
	}
	if plan.Verdict == Rejected {
		return 1
	}
	return 0
}

func printPlan(p *Plan) {
	fmt.Printf("Verdict: %s\n\n", p.Verdict)

	fmt.Println("Resources:")
	for _, r := range p.Resources {
		mark := statusMark(r.Status)
		line := fmt.Sprintf("  %s %-20s %-34s", mark, r.LogicalID, r.CFNType)
		if r.Kind != "" {
			line += "-> " + r.Kind
		} else {
			line += "-> (no kind)"
		}
		if !r.Included {
			line += "  [skipped: condition " + r.Condition + " is false]"
		}
		fmt.Println(line)
		if r.Included && r.Status == Partial && r.Note != "" {
			fmt.Printf("      caveat: %s\n", r.Note)
		}
	}

	// Only show an order for a plan that would actually provision — printing one next to
	// "nothing would be provisioned" reads as a promise the engine is refusing to make.
	if p.Verdict != Rejected && len(p.Order) > 0 {
		fmt.Printf("\nProvisioning order:\n  %s\n", strings.Join(p.Order, " -> "))
	}

	if len(p.Blockers) > 0 {
		fmt.Printf("\nBlockers (%d) — nothing would be provisioned:\n", len(p.Blockers))
		for _, b := range p.Blockers {
			fmt.Printf("  ✗ %s\n", b)
		}
	}

	fmt.Println()
	switch p.Verdict {
	case Provisionable:
		fmt.Println("All resources map to faithful kinds.")
	case ProvisionableWithCaveats:
		fmt.Println("Provisionable, but review the caveats above — some mappings are lossy.")
	case Rejected:
		fmt.Println("Rejected. Resolve every blocker above; this engine will not approximate.")
	}
}

func statusMark(s Status) string {
	switch s {
	case Supported:
		return "[ok  ]"
	case Partial:
		return "[part]"
	case Gated:
		return "[gate]"
	default:
		return "[no  ]"
	}
}

func runDeploy(args []string) int {
	opts := DeployOptions{Params: map[string]string{}, Wait: true, Timeout: 180 * time.Second}
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			i++
			if i >= len(args) {
				return "", false
			}
			return args[i], true
		}
		switch {
		case a == "-namespace" || a == "-n":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -namespace needs a value")
				return 2
			}
			opts.Namespace = v
		case a == "-stack-name":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -stack-name needs a value")
				return 2
			}
			opts.StackName = v
		case a == "-param":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -param needs K=V")
				return 2
			}
			k, val, ok := strings.Cut(v, "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "cfn: bad -param %q (want K=V)\n", v)
				return 2
			}
			opts.Params[k] = val
		case a == "-no-wait":
			opts.Wait = false
		case a == "-timeout":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -timeout needs seconds")
				return 2
			}
			secs, err := strconv.Atoi(v)
			if err != nil || secs <= 0 {
				fmt.Fprintf(os.Stderr, "cfn: bad -timeout %q\n", v)
				return 2
			}
			opts.Timeout = time.Duration(secs) * time.Second
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "cfn: unknown flag %q\n", a)
			return 2
		default:
			files = append(files, a)
		}
	}
	if opts.Namespace == "" || opts.StackName == "" {
		fmt.Fprintln(os.Stderr, "cfn: deploy requires -namespace and -stack-name")
		return 2
	}
	if len(files) != 1 {
		fmt.Fprintln(os.Stderr, "cfn: expected exactly one template file")
		return 2
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 2
	}

	fmt.Printf("Deploying stack %q into namespace %q…\n", opts.StackName, opts.Namespace)
	rec, err := Deploy(context.Background(), data, opts, kubectlApplier{namespace: opts.Namespace})
	if rec != nil {
		printStack(rec)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\ncfn: %v\n", err)
		return 1
	}
	fmt.Printf("\nStack %q is %s (%d resources).\n", rec.Name, rec.Status, len(rec.Resources))
	return 0
}

func printStack(rec *StackRecord) {
	fmt.Printf("\nStack %s [%s]\n", rec.Name, rec.Status)
	for _, r := range rec.Resources {
		fmt.Printf("  %-20s %s/%s -> %s\n", r.LogicalID, r.APIVersion, r.Kind, r.Name)
	}
	if rec.Message != "" {
		fmt.Printf("  message: %s\n", rec.Message)
	}
}
