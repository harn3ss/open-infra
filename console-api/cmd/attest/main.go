// Command attest assembles a compliance attestation from the live cluster and writes it as JSON +
// Markdown for signing. It does the assembly only; the CronJob around it (platform/security/
// compliance-attest.yaml) GPG-signs the output and stores it, signature and all, in the WORM audit
// store — so the attestation is dated, immutable, and verifiable with the published public key
// (the same key that signs the Terraform provider releases).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/harn3ss/open-infra/console-api/internal/attest"
)

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "attest: in-cluster config: %v\n", err)
		os.Exit(1)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attest: kube client: %v\n", err)
		os.Exit(1)
	}

	consoleNS := os.Getenv("CONSOLE_NS")
	if consoleNS == "" {
		consoleNS = "open-infra-console"
	}
	outDir := os.Getenv("OUTPUT_DIR")
	if outDir == "" {
		outDir = "/tmp"
	}

	anchorNS := os.Getenv("AUDIT_ANCHOR_NAMESPACE")
	if anchorNS == "" {
		anchorNS = "monitoring"
	}
	a := attest.Assemble(context.Background(), cs, consoleNS, anchorNS)
	a.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	blob, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "attest: marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outDir+"/attestation.json", blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "attest: write json: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outDir+"/attestation.md", []byte(attest.Markdown(a)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "attest: write md: %v\n", err)
		os.Exit(1)
	}
	// Print the JSON to stdout too (visible in CronJob logs / usable in a pipe).
	fmt.Println(string(blob))
}
