// iam-migrate rewrites the cluster's IAM objects into the AWS policy model, additively.
//
//	go run ./scripts/iam-migrate                 # dry run: print what it would write (default)
//	go run ./scripts/iam-migrate --json          # the same plan as JSON
//	go run ./scripts/iam-migrate --apply         # write it (kubectl patch / apply, as your kubeconfig)
//	go run ./scripts/iam-migrate --drop-legacy   # also remove the old forms it replaced (the cutover's last step)
//	go run ./scripts/iam-migrate --input DIR     # plan from DIR/{policies,groups,users,roles,clusterrolebindings}.json
//
// What it writes:
//   - kind: Policy with native data-plane statements gains spec.document, the same statements as an AWS
//     document (policyengine.ExportAWS, which round-trips), and each principal its appliesTo names gains
//     the policy in spec.policies — the AWS way to attach it.
//   - A Group's permission tier (spec.clusterRole open-infra-console / -poweruser / -readonly, ecr-pusher,
//     ecr-runtime-puller) gains its AWS managed policy (AdministratorAccess, PowerUserAccess,
//     ReadOnlyAccess, AmazonEC2ContainerRegistryPowerUser, AmazonEC2ContainerRegistryPullOnly). The
//     built-in groups, which exist only as ClusterRoleBindings to openinfra:<group>, become kind: Group
//     containers of those policies.
//   - A principal attaching a deprecated alias (administrator-access …) gains the AWS managed policy it
//     names (openinfra.dev/aws-equivalent). AWS's meaning can be broader: AdministratorAccess includes IAM.
//
// Without --drop-legacy nothing anyone holds changes: the old forms stay beside the new until the cutover.
// What has no faithful new form is kept and listed, never guessed.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	apply := flag.Bool("apply", false, "write the plan (default: dry run)")
	dropLegacy := flag.Bool("drop-legacy", false, "also remove the old forms the plan replaced")
	asJSON := flag.Bool("json", false, "print the plan as JSON")
	input := flag.String("input", "", "plan from JSON lists in this directory instead of the cluster")
	home := flag.String("home", "open-infra-console", "the IAM home namespace")
	kubectl := flag.String("kubectl", "kubectl", "the kubectl binary")
	flag.Parse()

	w, err := load(*input, *kubectl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iam-migrate:", err)
		os.Exit(1)
	}
	w.Home = *home
	plan := Build(w, *dropLegacy)
	if *asJSON {
		b, _ := json.MarshalIndent(plan, "", "  ")
		fmt.Println(string(b))
	} else {
		printPlan(plan)
	}
	if !*apply {
		fmt.Fprintln(os.Stderr, "\ndry run — nothing written (pass --apply to write it)")
		return
	}
	for _, c := range plan.Changes {
		if err := write(*kubectl, c); err != nil {
			fmt.Fprintf(os.Stderr, "iam-migrate: %s %s/%s: %v\n", c.Kind, c.Namespace, c.Name, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s %s/%s\n", c.Kind, c.Namespace, c.Name)
	}
}

func printPlan(p Plan) {
	for _, c := range p.Changes {
		verb := "patch"
		if c.Create {
			verb = "create"
		}
		b, _ := json.Marshal(c.Patch)
		fmt.Printf("%s %s %s/%s — %s\n    spec %s\n", verb, c.Kind, c.Namespace, c.Name, c.Why, b)
	}
	for _, k := range p.Kept {
		fmt.Println("kept:", k)
	}
	for _, n := range p.Notes {
		fmt.Println("note:", n)
	}
	fmt.Println(p.Summary())
}

var resources = map[string]string{"Policy": "policies.iam.openinfra.dev", "Group": "groups.iam.openinfra.dev",
	"User": "users.iam.openinfra.dev", "Role": "roles.iam.openinfra.dev"}

func write(kubectl string, c Change) error {
	if c.Create {
		obj := map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": c.Kind,
			"metadata": map[string]any{"name": c.Name, "namespace": c.Namespace,
				"labels": map[string]any{"openinfra.dev/created-by": "iam-migrate"}},
			"spec": c.Patch}
		b, _ := json.Marshal(obj)
		return run(kubectl, b, "apply", "-f", "-")
	}
	b, _ := json.Marshal(map[string]any{"spec": c.Patch})
	// A Crossplane claim's spec is kept in step with its composite's: a field removed from the claim alone
	// comes back from the composite on the next sync. So a removal is written to the composite
	// (spec.resourceRef) first, then to the claim.
	if removesFields(c.Patch) {
		ref, err := output(kubectl, "-n", c.Namespace, "get", resources[c.Kind], c.Name, "-o",
			"jsonpath={.spec.resourceRef.apiVersion} {.spec.resourceRef.kind} {.spec.resourceRef.name}")
		if err != nil {
			return err
		}
		if f := strings.Fields(ref); len(f) == 3 {
			group, _, _ := strings.Cut(f[0], "/")
			composite := strings.ToLower(f[1]) + "s." + group
			if err := run(kubectl, nil, "patch", composite, f[2], "--type", "merge", "-p", string(b)); err != nil {
				return fmt.Errorf("composite %s %s: %w", composite, f[2], err)
			}
		}
	}
	return run(kubectl, nil, "-n", c.Namespace, "patch", resources[c.Kind], c.Name, "--type", "merge", "-p", string(b))
}

// removesFields reports whether a merge patch removes a field (a null value).
func removesFields(patch map[string]any) bool {
	for _, v := range patch {
		if v == nil {
			return true
		}
		if m, ok := v.(map[string]any); ok && removesFields(m) {
			return true
		}
	}
	return false
}

func output(kubectl string, args ...string) (string, error) {
	out, err := exec.Command(kubectl, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v", kubectl, strings.Join(args, " "), err)
	}
	return string(out), nil
}

func run(kubectl string, stdin []byte, args ...string) error {
	cmd := exec.Command(kubectl, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// load reads the IAM objects and the openinfra:<group> ClusterRoleBindings, from the cluster or a directory.
func load(dir, kubectl string) (World, error) {
	read := func(name, resource string) ([]byte, error) {
		if dir != "" {
			return os.ReadFile(filepath.Join(dir, name+".json"))
		}
		cmd := exec.Command(kubectl, "get", resource, "-A", "-o", "json")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("kubectl get %s: %v: %s", resource, err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
	var w World
	for _, k := range []struct {
		file, kind string
		into       *[]Obj
	}{{"policies", "Policy", &w.Policies}, {"groups", "Group", &w.Groups}, {"users", "User", &w.Users}, {"roles", "Role", &w.Roles}} {
		b, err := read(k.file, resources[k.kind])
		if err != nil {
			return w, err
		}
		objs, err := parseList(b, k.kind)
		if err != nil {
			return w, fmt.Errorf("%s: %w", k.file, err)
		}
		*k.into = objs
	}
	b, err := read("clusterrolebindings", "clusterrolebindings.rbac.authorization.k8s.io")
	if err != nil {
		return w, err
	}
	var crbs struct {
		Items []struct {
			Metadata struct{ Name string }
			RoleRef  struct{ Name string } `json:"roleRef"`
			Subjects []struct{ Kind, Name string }
		}
	}
	if err := json.Unmarshal(b, &crbs); err != nil {
		return w, fmt.Errorf("clusterrolebindings: %w", err)
	}
	for _, it := range crbs.Items {
		if strings.HasPrefix(it.Metadata.Name, "openinfra-group-") {
			continue // a kind: Group's own binding: the Group carries the tier
		}
		for _, s := range it.Subjects {
			if s.Kind == "Group" && strings.HasPrefix(s.Name, "openinfra:") {
				g := strings.TrimPrefix(s.Name, "openinfra:")
				if g == "users" || g == "root" {
					continue // the implicit group and break-glass are not policy containers
				}
				w.Bindings = append(w.Bindings, Binding{Name: it.Metadata.Name, ClusterRole: it.RoleRef.Name, Group: g})
			}
		}
	}
	return w, nil
}

func parseList(b []byte, kind string) ([]Obj, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name, Namespace string
				Labels          map[string]string
				Annotations     map[string]string
			}
			Spec map[string]any
		}
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	out := make([]Obj, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, Obj{Kind: kind, Name: it.Metadata.Name, Namespace: it.Metadata.Namespace,
			Labels: it.Metadata.Labels, Annotations: it.Metadata.Annotations, Spec: it.Spec})
	}
	return out, nil
}
