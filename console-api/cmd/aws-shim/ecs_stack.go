package main

import (
	"context"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
)

// A service or cluster a CloudFormation stack creates is, on ECS, a service or cluster like any other:
// DescribeServices and ListServices report the service, DescribeClusters and ListClusters the cluster, and a
// service can be created in the cluster. They are found in the account's stack records (the CloudFormation
// front door's), not in this front door's own: a stack's AWS::ECS::Service is the kind: Application the
// stack made (its record's resource of the same logical id), in the stack's namespace, and its Ref is the
// service's ARN (service/<cluster>/<name>); an AWS::ECS::Cluster provisions nothing, and its Ref is the
// cluster's name.

const (
	ecsServiceType = "AWS::ECS::Service"
	ecsClusterType = "AWS::ECS::Cluster"
)

// ecsStackService is a service a CloudFormation stack made.
type ecsStackService struct {
	name, cluster string
	app, ns       string // its kind: Application and the namespace it is in (its stack's)
	// taskDefinition is the ARN the service's TaskDefinition names, as the stack resolves it.
	taskDefinition string
	launchType     string
	createdAt      string // the stack's creation time
}

// stackECS is the services and clusters the account's stacks made (none when this front door is not given
// the stack records).
func (h *ecsDoorway) stackECS(ctx context.Context) (services []ecsStackService, clusters []string) {
	if h.stacks == nil {
		return nil, nil
	}
	recs, err := h.stacks(ctx)
	if err != nil {
		h.logger.Warn("ecs: the account's stacks could not be read", "error", err.Error())
		return nil, nil
	}
	for _, rec := range recs {
		apps := map[string]string{} // logical id -> the Application the stack made for it
		for _, r := range append(append([]cfn.StackResource{}, rec.Resources...), rec.Pending...) {
			if r.Kind == "Application" && r.Name != "" && (r.Type == "" || r.Type == ecsServiceType) {
				apps[r.LogicalID] = r.Name
			}
		}
		for _, tr := range templateResources(rec, recs, ecsServiceType, ecsClusterType) {
			if tr.Type == ecsClusterType {
				if tr.Ref != "" {
					clusters = append(clusters, tr.Ref)
				}
				continue
			}
			app, made := apps[tr.LogicalID]
			cluster, name, ok := ecsServiceARNParts(tr.Ref)
			if !made || !ok {
				continue // not made yet (or no longer)
			}
			services = append(services, ecsStackService{name: name, cluster: cluster, app: app, ns: rec.Namespace,
				taskDefinition: fnStr(tr.Properties["TaskDefinition"]), launchType: fnStr(tr.Properties["LaunchType"]),
				createdAt: rec.CreatedAt})
		}
	}
	return services, clusters
}

// ecsServiceAt is where a service is: the applier that reads its Application (in its namespace), the
// Application's name, and what the service's record says of it.
type ecsServiceAt struct {
	ap                                    *impersonatingApplier
	app, cluster                          string
	taskDefinition, createdAt, launchType string
	history                               []ecsTaskDefRecord
}

// locateService finds the service name in cluster: one created through ECS (its record in this front
// door's store), else one a CloudFormation stack made, read in its stack's namespace. With neither it is
// where a service created through ECS would be, which its caller finds missing.
func (h *ecsDoorway) locateService(ctx context.Context, ap *impersonatingApplier, name, cluster string) ecsServiceAt {
	at := ecsServiceAt{ap: ap, app: ecsAppObject(ctx, ap, ecsName(name)), cluster: cluster}
	if ref, found, _ := h.getServiceRef(ctx, name); found {
		at.taskDefinition, at.createdAt = firstString(ref.Body, "taskDefinition"), ref.CreatedAt
		at.launchType, at.history = firstString(ref.Body, "launchType"), ref.History
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
	}
	return at
}

// stackService is the service named name in cluster that a stack made.
func (h *ecsDoorway) stackService(ctx context.Context, cluster, name string) (ecsStackService, bool) {
	services, _ := h.stackECS(ctx)
	for _, s := range services {
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
	_, clusters := h.stackECS(ctx)
	for _, c := range clusters {
		if c == cluster {
			return true, nil
		}
	}
	return false, nil
}

// stackClusters is the clusters the account's stacks made that are not also clusters created through ECS
// (a name is one cluster of the account), each once.
func (h *ecsDoorway) stackClusters(ctx context.Context) []string {
	_, clusters := h.stackECS(ctx)
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
