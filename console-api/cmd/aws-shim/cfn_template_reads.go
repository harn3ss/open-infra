// What the front doors read from a stack's recorded template for a resource that provisions nothing of its
// own — an internet gateway, a route table and its associations, an instance profile (cfn/folded.go): the
// resource is the stack's, with the id its Ref gave the stack (cfn.TemplateResourcesOf), and it exists
// while its stack holds it.
package main

import (
	"context"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
)

// accountStacks is the stack records of the caller's account, by name: a member account's are its home
// namespace's, the management account's the door's own (accountNamespace) — exactly the records the
// management account always had. The exports a template imports resolve within the same account.
func accountStacks(ctx context.Context, door *cfnDoorway) ([]*cfn.StackRecord, error) {
	all, err := (&cloudFrontHandler{cfn: door}).stackRecords(ctx)
	if err != nil {
		return nil, err
	}
	ns := accountNamespace(ctx, door.ns)
	var mine []*cfn.StackRecord
	for _, rec := range all {
		if rec.Namespace == ns || (rec.Namespace == "" && !isMemberRequest(ctx)) {
			mine = append(mine, rec)
		}
	}
	return mine, nil
}

// stackHolds reports whether a stack's resources that provision nothing of their own exist: from the start
// of its create until it, or its rolled-back create, is deleted (cfn.FoldedStatusWithoutCarrier).
func stackHolds(rec *cfn.StackRecord) bool {
	return !createNotStarted(rec) && cfn.FoldedStatusWithoutCarrier(rec.Status) != "DELETE_COMPLETE"
}

// templateTags are a template resource's Tags property as a map (the aws: prefix is AWS's own and never a
// template's).
func templateTags(tr cfn.TemplateResource) map[string]string {
	out := map[string]string{}
	list, _ := tr.Properties["Tags"].([]any)
	for _, t := range list {
		m, _ := t.(map[string]any)
		if k := fnStr(m["Key"]); k != "" && !strings.HasPrefix(k, "aws:") {
			out[k] = fnStr(m["Value"])
		}
	}
	return out
}

// stackResourceTags are an EC2 resource's tags as AWS reports one a stack made: the template's Tags and the
// aws:cloudformation:* tags CloudFormation adds to every resource of the stack.
func stackResourceTags(door *cfnDoorway, rec *cfn.StackRecord, tr cfn.TemplateResource) map[string]string {
	tags := templateTags(tr)
	tags["aws:cloudformation:stack-name"] = rec.Name
	tags["aws:cloudformation:stack-id"] = door.idOf(rec)
	tags["aws:cloudformation:logical-id"] = tr.LogicalID
	return tags
}
