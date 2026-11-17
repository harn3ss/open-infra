package main

import (
	"context"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
)

// A service, cluster or task definition a CloudFormation stack creates is, on ECS, one like any other:
// DescribeServices and ListServices report the service, DescribeClusters and ListClusters the cluster,
// DescribeTaskDefinition the task definition, and a service can be created in the cluster. They are found in
// the account's stack records (the CloudFormation front door's), not in this front door's own: a stack's
// AWS::ECS::Service is the kind: Application the stack made (its record's resource of the same logical id),
// in the stack's namespace, and its Ref is the service's ARN (service/<cluster>/<name>); an AWS::ECS::Cluster
// and an AWS::ECS::TaskDefinition provision nothing of their own, and their Refs are the cluster's name and
// the task definition's ARN (task-definition/<family>:<revision>).

const (
	ecsServiceType  = "AWS::ECS::Service"
	ecsClusterType  = "AWS::ECS::Cluster"
	ecsTaskDefType  = "AWS::ECS::TaskDefinition"
	ecsTaskDefInfix = ":task-definition/"
)

// ecsStackService is a service a CloudFormation stack made.
type ecsStackService struct {
	name, cluster string
	app, ns       string // its kind: Application and the namespace it is in (its stack's)
	// taskDefinition is the ARN the service's TaskDefinition names, as the stack resolves it.
	taskDefinition string
	launchType     string
	createdAt      string // the stack's creation time
	// network is its NetworkConfiguration in the ECS API's form (nil: none).
	network map[string]any
}

// ecsStackTaskDef is a task definition a CloudFormation stack made: its family and revision, and its
// properties in the ECS API's form.
type ecsStackTaskDef struct {
	family   string
	revision int
	body     map[string]any
}

// ecsStackView is what the account's stacks made in ECS.
type ecsStackView struct {
	services []ecsStackService
	clusters []string
	taskDefs []ecsStackTaskDef
}

// stackECS is the services, clusters and task definitions the account's stacks made (none when this front
// door is not given the stack records). A stack rolled back, failed or being deleted has made none.
func (h *ecsDoorway) stackECS(ctx context.Context) ecsStackView {
	var v ecsStackView
	if h.stacks == nil {
		return v
	}
	recs, err := h.stacks(ctx)
	if err != nil {
		h.logger.Warn("ecs: the account's stacks could not be read", "error", err.Error())
		return v
	}
	for _, rec := range recs {
		if st := rec.Status; strings.HasPrefix(st, "ROLLBACK") || strings.HasPrefix(st, "DELETE") || strings.HasSuffix(st, "FAILED") {
			continue
		}
		apps := map[string]string{} // logical id -> the Application the stack made for it
		for _, r := range append(append([]cfn.StackResource{}, rec.Resources...), rec.Pending...) {
			if r.Kind == "Application" && r.Name != "" && (r.Type == "" || r.Type == ecsServiceType) {
				apps[r.LogicalID] = r.Name
			}
		}
		for _, tr := range templateResources(rec, recs, ecsServiceType, ecsClusterType, ecsTaskDefType) {
			switch tr.Type {
			case ecsClusterType:
				if tr.Ref != "" {
					v.clusters = append(v.clusters, tr.Ref)
				}
			case ecsTaskDefType:
				if i := strings.Index(tr.Ref, ecsTaskDefInfix); i >= 0 {
					if family, rev := parseTaskDef(tr.Ref); family != "" && rev > 0 {
						body, _ := cfnToECS(tr.Properties).(map[string]any)
						v.taskDefs = append(v.taskDefs, ecsStackTaskDef{family: family, revision: rev, body: body})
					}
				}
			case ecsServiceType:
				app, made := apps[tr.LogicalID]
				cluster, name, ok := ecsServiceARNParts(tr.Ref)
				if !made || !ok {
					continue // not made yet (or no longer)
				}
				v.services = append(v.services, ecsStackService{name: name, cluster: cluster, app: app, ns: rec.Namespace,
					taskDefinition: fnStr(tr.Properties["TaskDefinition"]), launchType: fnStr(tr.Properties["LaunchType"]),
					network:   ecsNetworkConfiguration(tr.Properties["NetworkConfiguration"]),
					createdAt: rec.CreatedAt})
			}
		}
	}
	return v
}

// stackTaskDef is the task definition family:revision a stack made (revision 0: the family's latest).
func (h *ecsDoorway) stackTaskDef(ctx context.Context, family string, rev int) (ecsStackTaskDef, bool) {
	var best ecsStackTaskDef
	found := false
	for _, td := range h.stackECS(ctx).taskDefs {
		if td.family == family && (td.revision == rev || (rev == 0 && td.revision > best.revision)) {
			best, found = td, true
		}
	}
	return best, found
}

// ecsUserKeyed are the ECS properties whose keys are the user's own (a log driver's options, Docker labels),
// kept as written when a stack's properties take the ECS API's form.
var ecsUserKeyed = map[string]bool{"Options": true, "DockerLabels": true, "DriverOpts": true, "Labels": true}

// cfnToECS is a stack's ECS properties in the ECS API's form: each CloudFormation property name with its
// first letter lower-cased (EFSVolumeConfiguration as efsVolumeConfiguration), the user's own keys kept.
func cfnToECS(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			key := ecsKey(k)
			if ecsUserKeyed[k] {
				out[key] = val
				continue
			}
			out[key] = cfnToECS(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = cfnToECS(t[i])
		}
		return out
	default:
		return v
	}
}

func ecsKey(k string) string {
	for camel, pascal := range cfnKeyOverrides {
		if k == pascal {
			return camel
		}
	}
	return lowerFirst(k)
}

// ecsServiceAt is where a service is: the applier that reads its Application (in its namespace), the
// Application's name, and what the service's record says of it.
type ecsServiceAt struct {
	ap                                    *impersonatingApplier
	app, cluster                          string
	taskDefinition, createdAt, launchType string
	history                               []ecsTaskDefRecord
	network                               map[string]any // its networkConfiguration (nil: none)
}

// ecsNetworkConfiguration is a service's NetworkConfiguration (a stack's property, or the ECS API's own)
// in the ECS API's form: awsvpcConfiguration with its subnets, security groups and assignPublicIp.
func ecsNetworkConfiguration(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	if _, cfnForm := m["AwsvpcConfiguration"]; cfnForm {
		m, _ = cfnToECS(m).(map[string]any)
	}
	return m
}

// locateService finds the service name in cluster: one created through ECS (its record in this front
// door's store), else one a CloudFormation stack made, read in its stack's namespace. With neither it is
// where a service created through ECS would be, which its caller finds missing.
func (h *ecsDoorway) locateService(ctx context.Context, ap *impersonatingApplier, name, cluster string) ecsServiceAt {
	at := ecsServiceAt{ap: ap, app: ecsAppObject(ctx, ap, ecsName(name)), cluster: cluster}
	if ref, found, _ := h.getServiceRef(ctx, name); found {
		at.taskDefinition, at.createdAt = firstString(ref.Body, "taskDefinition"), ref.CreatedAt
		at.launchType, at.history = firstString(ref.Body, "launchType"), ref.History
		at.network = ecsNetworkConfiguration(ref.Body["networkConfiguration"])
		if ref.Cluster != "" {
			at.cluster = ref.Cluster
		}
		return at
	}
	if ss, ok := h.stackService(ctx, cluster, name); ok {
		in := *ap
		in.ns = ss.ns
		at.ap, at.app = &in, ss.app
		at.taskDefinition, at.createdAt, at.launchType = ss.taskDefinition, ss.createdAt, ss.launchType
		at.network = ss.network
	}
	return at
}

// stackService is the service named name in cluster that a stack made.
func (h *ecsDoorway) stackService(ctx context.Context, cluster, name string) (ecsStackService, bool) {
	for _, s := range h.stackECS(ctx).services {
		if s.name == name && s.cluster == cluster {
			return s, true
		}
	}
	return ecsStackService{}, false
}

// clusterExists reports whether cluster is one of the account's: created through ECS, or by a stack.
func (h *ecsDoorway) clusterExists(ctx context.Context, cluster string) (bool, error) {
	if _, found, err := h.getCluster(ctx, cluster); err != nil || found {
		return found, err
	}
	for _, c := range h.stackECS(ctx).clusters {
		if c == cluster {
			return true, nil
		}
	}
	return false, nil
}

// stackClusters is the clusters the account's stacks made that are not also clusters created through ECS
// (a name is one cluster of the account), each once.
func (h *ecsDoorway) stackClusters(ctx context.Context) []string {
	clusters := h.stackECS(ctx).clusters
	seen := map[string]bool{}
	for _, c := range h.listClusters(ctx) {
		seen[c.ClusterName] = true
	}
	var out []string
	for _, c := range clusters {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// ecsServiceARNParts splits a service ARN (arn:aws:ecs:<region>:<account>:service/<cluster>/<name>) into
// its cluster and name.
func ecsServiceARNParts(arn string) (cluster, name string, ok bool) {
	i := strings.Index(arn, ":service/")
	if !strings.HasPrefix(arn, "arn:") || i < 0 {
		return "", "", false
	}
	cluster, name, ok = strings.Cut(arn[i+len(":service/"):], "/")
	return cluster, name, ok && cluster != "" && name != "" && !strings.Contains(name, "/")
}

// requestedCluster is the cluster a DescribeServices entry names: the cluster of a service ARN, else the
// request's cluster.
func requestedCluster(raw, cluster string) string {
	if c, _, ok := ecsServiceARNParts(raw); ok {
		return c
	}
	return cluster
}
