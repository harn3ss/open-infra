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
	case "changeset":
		os.Exit(runChangeSet(os.Args[2:]))
	case "update":
		os.Exit(runUpdate(os.Args[2:]))
	case "destroy":
		os.Exit(runDestroy(os.Args[2:]))
	case "drift":
		os.Exit(runDrift(os.Args[2:]))
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
  cfn plan      [-param K=V ...] [-stack-name NAME] [-json] <template>
  cfn deploy     -namespace NS -stack-name NAME [-param K=V ...] [-no-wait] [-timeout SECS] <template>
  cfn changeset  -namespace NS -stack-name NAME [-param K=V ...] <template>
  cfn update     -namespace NS -stack-name NAME [-param K=V ...] [-no-wait] [-timeout SECS] <template>
  cfn destroy    -namespace NS -stack-name NAME [-no-wait] [-timeout SECS]
  cfn drift      -namespace NS -stack-name NAME

plan      (read-only) reports whether open-infra can provision a template, with caveats, or
          not — and exactly why. Provisions nothing.
deploy    provisions a stack live, fail-closed: it refuses unless the whole template maps and
          every property translates, applies in dependency order, records the stack, and rolls
          back on failure leaving no orphans.
changeset (read-only) diffs a template against the current stack — what would be Added,
          Modified, Removed, or left Unchanged.
update    applies that change set, rolling back to the exact prior stack if any step fails.
destroy   tears a stack down in reverse dependency order, honoring DeletionPolicy (Retain
          keeps a resource; Snapshot is refused), then removes the stack record.
drift     (read-only) compares the recorded stack against the live cluster and reports any
          resource that was changed or deleted out of band. Exit 0 in sync, 1 if drifted.
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

// parseStackFlags parses the flags shared by deploy/update/changeset, returning the options,
// the single template file, and a non-negative exit code on error (-1 = ok).
func parseStackFlags(cmd string, args []string) (DeployOptions, string, int) {
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
				return opts, "", 2
			}
			opts.Namespace = v
		case a == "-stack-name":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -stack-name needs a value")
				return opts, "", 2
			}
			opts.StackName = v
		case a == "-param":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -param needs K=V")
				return opts, "", 2
			}
			k, val, ok := strings.Cut(v, "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "cfn: bad -param %q (want K=V)\n", v)
				return opts, "", 2
			}
			opts.Params[k] = val
		case a == "-no-wait":
			opts.Wait = false
		case a == "-timeout":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -timeout needs seconds")
				return opts, "", 2
			}
			secs, err := strconv.Atoi(v)
			if err != nil || secs <= 0 {
				fmt.Fprintf(os.Stderr, "cfn: bad -timeout %q\n", v)
				return opts, "", 2
			}
			opts.Timeout = time.Duration(secs) * time.Second
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "cfn: unknown flag %q\n", a)
			return opts, "", 2
		default:
			files = append(files, a)
		}
	}
	if opts.Namespace == "" || opts.StackName == "" {
		fmt.Fprintf(os.Stderr, "cfn: %s requires -namespace and -stack-name\n", cmd)
		return opts, "", 2
	}
	if len(files) != 1 {
		fmt.Fprintln(os.Stderr, "cfn: expected exactly one template file")
		return opts, "", 2
	}
	return opts, files[0], -1
}

func runDeploy(args []string) int {
	opts, file, code := parseStackFlags("deploy", args)
	if code >= 0 {
		return code
	}
	data, err := os.ReadFile(file)
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

func runChangeSet(args []string) int {
	opts, file, code := parseStackFlags("changeset", args)
	if code >= 0 {
		return code
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 2
	}
	cs, _, _, err := BuildChangeSet(context.Background(), data, opts, kubectlApplier{namespace: opts.Namespace})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 1
	}
	printChangeSet(cs)
	return 0
}

func runUpdate(args []string) int {
	opts, file, code := parseStackFlags("update", args)
	if code >= 0 {
		return code
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 2
	}
	ap := kubectlApplier{namespace: opts.Namespace}
	cs, _, _, err := BuildChangeSet(context.Background(), data, opts, ap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 1
	}
	printChangeSet(cs)
	if !cs.Exists {
		fmt.Fprintf(os.Stderr, "\ncfn: no stack %q to update — use deploy\n", opts.StackName)
		return 1
	}
	if !cs.hasChanges() {
		fmt.Println("\nNo changes — stack is already up to date.")
		return 0
	}
	fmt.Printf("\nApplying update to stack %q…\n", opts.StackName)
	rec, err := Update(context.Background(), data, opts, ap)
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

func runDestroy(args []string) int {
	opts := DeployOptions{Params: map[string]string{}, Wait: true, Timeout: 180 * time.Second}
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
		default:
			fmt.Fprintf(os.Stderr, "cfn: unexpected argument %q (destroy takes no template)\n", a)
			return 2
		}
	}
	if opts.Namespace == "" || opts.StackName == "" {
		fmt.Fprintln(os.Stderr, "cfn: destroy requires -namespace and -stack-name")
		return 2
	}
	fmt.Printf("Destroying stack %q in namespace %q…\n", opts.StackName, opts.Namespace)
	rec, err := Destroy(context.Background(), opts, kubectlApplier{namespace: opts.Namespace})
	if err != nil {
		if rec != nil {
			printStack(rec)
		}
		fmt.Fprintf(os.Stderr, "\ncfn: %v\n", err)
		return 1
	}
	if len(rec.Resources) > 0 {
		fmt.Printf("\nStack %q is DELETE_COMPLETE. Retained (now unmanaged):\n", rec.Name)
		for _, r := range rec.Resources {
			fmt.Printf("  %-20s %s/%s\n", r.LogicalID, r.Kind, r.Name)
		}
	} else {
		fmt.Printf("\nStack %q is DELETE_COMPLETE.\n", rec.Name)
	}
	return 0
}

func runDrift(args []string) int {
	var namespace, stackName string
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
			namespace = v
		case a == "-stack-name":
			v, ok := next()
			if !ok {
				fmt.Fprintln(os.Stderr, "cfn: -stack-name needs a value")
				return 2
			}
			stackName = v
		default:
			fmt.Fprintf(os.Stderr, "cfn: unexpected argument %q (drift takes no template)\n", a)
			return 2
		}
	}
	if namespace == "" || stackName == "" {
		fmt.Fprintln(os.Stderr, "cfn: drift requires -namespace and -stack-name")
		return 2
	}
	opts := DeployOptions{Namespace: namespace, StackName: stackName}
	report, err := DetectDrift(context.Background(), opts, kubectlApplier{namespace: namespace})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfn: %v\n", err)
		return 2
	}
	printDrift(report)
	if report.InSync {
		return 0
	}
	return 1
}

func printDrift(r *DriftReport) {
	if r.InSync {
		fmt.Printf("Stack %q is IN SYNC with the cluster.\n", r.StackName)
	} else {
		fmt.Printf("Stack %q has DRIFTED from the cluster:\n", r.StackName)
	}
	for _, rd := range r.Resources {
		switch rd.Status {
		case InSync:
			fmt.Printf("  = %-20s %s/%s in sync\n", rd.LogicalID, rd.Kind, rd.Name)
		case Modified:
			fmt.Printf("  ~ %-20s %s/%s changed on the cluster: %s\n", rd.LogicalID, rd.Kind, rd.Name, strings.Join(rd.DriftedFields, ", "))
		case Deleted:
			fmt.Printf("  - %-20s %s/%s deleted out of band\n", rd.LogicalID, rd.Kind, rd.Name)
		}
	}
	if !r.InSync {
		fmt.Println("\nDrift is reported, not reconciled — resolve it by updating the stack or the cluster deliberately.")
	}
}

func printChangeSet(cs *ChangeSet) {
	if !cs.Exists {
		fmt.Printf("Change set for %q (new stack — every resource is an Add):\n", cs.StackName)
	} else {
		fmt.Printf("Change set for %q:\n", cs.StackName)
	}
	for _, c := range cs.Changes {
		mark := map[ChangeAction]string{Add: "+ ", Modify: "~ ", Remove: "- ", Unchanged: "  "}[c.Action]
		fmt.Printf("  %s%-8s %-20s %s/%s\n", mark, c.Action, c.LogicalID, c.Kind, c.Name)
		for _, cav := range c.Caveats {
			fmt.Printf("        caveat: %s\n", cav)
		}
	}
	if !cs.hasChanges() {
		fmt.Println("  (no changes)")
	}
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
