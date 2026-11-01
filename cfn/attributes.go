package cfn

import (
	"fmt"
)

// Resource attributes (DeletionPolicy, UpdateReplacePolicy, CreationPolicy, UpdatePolicy, Metadata).
// DeletionPolicy is honored (Retain, RetainExceptOnCreate; Snapshot refuses a delete it cannot honor).
// The others change nothing on open-infra, so each one a template sets is a fidelity line: a pass never
// reads as having done what the attribute asked for.

var deletionPolicies = map[string]bool{"Delete": true, "Retain": true, "RetainExceptOnCreate": true, "Snapshot": true}
var updateReplacePolicies = map[string]bool{"Delete": true, "Retain": true, "Snapshot": true}

// authoringMetadata are Metadata keys only template tooling reads (the console's parameter grouping,
// the visual designer, linters). They change nothing at deploy time on AWS either.
var authoringMetadata = map[string]bool{
	"AWS::CloudFormation::Interface": true, "AWS::CloudFormation::Designer": true,
	"cfn-lint": true, "cfn_nag": true, "checkov": true,
}

// attributeBlockers are the resource's attribute errors CloudFormation itself rejects: an undefined
// resource key, or a DeletionPolicy / UpdateReplacePolicy value it does not define.
func attributeBlockers(id string, r Resource) []string {
	var out []string
	for _, k := range r.unknownKeys {
		out = append(out, fmt.Sprintf("%s: %q is not a CloudFormation resource attribute — refusing rather than ignoring it", id, k))
	}
	if r.DeletionPolicy != "" && !deletionPolicies[r.DeletionPolicy] {
		out = append(out, fmt.Sprintf("%s: DeletionPolicy %q is not one of Delete, Retain, RetainExceptOnCreate, Snapshot", id, r.DeletionPolicy))
	}
	if r.UpdateReplacePolicy != "" && !updateReplacePolicies[r.UpdateReplacePolicy] {
		out = append(out, fmt.Sprintf("%s: UpdateReplacePolicy %q is not one of Delete, Retain, Snapshot", id, r.UpdateReplacePolicy))
	}
	return out
}

// attributeCaveats are the fidelity lines for the attributes a resource sets that open-infra does not act on.
func attributeCaveats(r Resource) []string {
	var out []string
	if r.DeletionPolicy == "Snapshot" {
		out = append(out, "DeletionPolicy Snapshot cannot be honored — open-infra takes no snapshot on delete, so deleting this stack is refused while the resource is in it")
	}
	if r.CreationPolicy != nil {
		cp, _ := r.CreationPolicy.(map[string]any)
		// A ResourceSignal is waited for (signals.go): no caveat.
		if _, ok := cp["AutoScalingCreationPolicy"]; ok {
			out = append(out, "CreationPolicy AutoScalingCreationPolicy is not honored")
		}
		if len(cp) == 0 {
			out = append(out, "CreationPolicy is not honored")
		}
	}
	if r.UpdatePolicy != nil {
		out = append(out, "UpdatePolicy is not honored — open-infra updates a resource in place (no rolling or replacing update, no AutoScaling/Lambda alias policy)")
	}
	if r.UpdateReplacePolicy != "" {
		out = append(out, "UpdateReplacePolicy "+r.UpdateReplacePolicy+" has no effect — open-infra updates a resource in place and never replaces it on update")
	}
	// Metadata is kept with the template and returned by DescribeStackResource, which is what cfn-init
	// reads: AWS::CloudFormation::Init runs when the guest runs cfn-init against this front door, as on AWS.
	if _, ok := r.Metadata["AWS::CloudFormation::Authentication"]; ok {
		out = append(out, "Metadata AWS::CloudFormation::Authentication is returned to cfn-init but open-infra does not act on it — cfn-init fetches sources with the instance role's credentials only")
	}
	return out
}
