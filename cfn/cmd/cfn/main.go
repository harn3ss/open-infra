// Command cfn is the CloudFormation engine's CLI (plan/deploy/changeset/update/destroy/drift).
// The engine itself is the importable package github.com/harn3ss/open-infra/cfn — the aws-shim's
// CloudFormation doorway imports that package and drives the same lifecycle functions through an
// impersonating Applier, so the CLI and the doorway share one engine.
package main

import "github.com/harn3ss/open-infra/cfn"

func main() { cfn.Main() }
