package awsaction

import (
	"fmt"
	"strings"
)

// OperatorPrefix is the service prefix of the operator's surface: raw Kubernetes objects and the
// platform's composites. Only AdministratorAccess (Action "*") covers it.
const OperatorPrefix = "openinfra-operator"

// operatorKinds names the Kind of the raw Kubernetes resources the console shows, for AWS-shaped action
// names (openinfra-operator:ListPods). A resource not listed is named from its plural.
var operatorKinds = map[string]string{
	"pods": "Pod", "nodes": "Node", "namespaces": "Namespace", "services": "Service", "endpoints": "Endpoints",
	"events": "Event", "secrets": "Secret", "configmaps": "ConfigMap", "persistentvolumeclaims": "PersistentVolumeClaim",
	"persistentvolumes": "PersistentVolume", "serviceaccounts": "ServiceAccount", "deployments": "Deployment",
	"statefulsets": "StatefulSet", "daemonsets": "DaemonSet", "replicasets": "ReplicaSet", "jobs": "Job",
	"cronjobs": "CronJob", "ingresses": "Ingress", "networkpolicies": "NetworkPolicy", "storageclasses": "StorageClass",
	"roles": "Role", "rolebindings": "RoleBinding", "clusterroles": "ClusterRole", "clusterrolebindings": "ClusterRoleBinding",
	"customresourcedefinitions": "CustomResourceDefinition", "resourcequotas": "ResourceQuota", "limitranges": "LimitRange",
	"horizontalpodautoscalers": "HorizontalPodAutoscaler", "poddisruptionbudgets": "PodDisruptionBudget",
	"leases": "Lease", "endpointslices": "EndpointSlice",
}

var operatorVerb = map[Verb]string{Get: "Get", List: "List", Create: "Create", Update: "Update", Delete: "Delete"}

// ForKubernetes is the primary (action, ARN) of one Kubernetes API request in account:
//   - a claim kind's own resource (buckets, users.iam …), and its status subresource, is that kind's
//     AWS action on its ARN;
//   - an openinfra.dev resource the table doesn't know is not authorized (ok=false), so a new kind is
//     denied until it is mapped;
//   - anything else — raw objects, the composites (xbuckets), other groups' CRDs, subresources such as
//     pods/log and pods/exec — is the operator's surface: openinfra-operator:<Verb><Kind>[<Sub>] on
//     arn:…:openinfra-operator:<region>:<account>:<resource>/<namespace>/<name>.
//
// ok=false also for a verb no IAM policy can grant (escalate, bind, impersonate …) and an empty
// resource.
func ForKubernetes(verb, group, resource, namespace, name, account string) (action, arn string, ok bool) {
	return Scope{Account: account}.ForKubernetes(verb, group, resource, namespace, name)
}

// ForKubernetes is the package's ForKubernetes in scope s.
func (s Scope) ForKubernetes(verb, group, resource, namespace, name string) (action, arn string, ok bool) {
	v, vok := NormalizeVerb(verb)
	if !vok || resource == "" {
		return "", "", false
	}
	res, sub, _ := strings.Cut(resource, "/")
	if e, found := byResource[group+"/"+res]; found && (sub == "" || sub == "status") {
		a, aok := e.Action(v)
		if !aok {
			return "", "", false
		}
		return a, e.resourceFor(s, v, name, nil), true
	}
	if isPlatformGroup(group) && !isComposite(group, res) {
		return "", "", false // an openinfra kind the table doesn't map: deny until it is
	}
	return s.operator(v, group, res, sub, namespace, name), s.operatorARN(v, res, namespace, name), true
}

func isPlatformGroup(group string) bool {
	return group == groupPlatform || group == groupIAM
}

// isComposite reports whether res is a claim kind's cluster-scoped composite (xbuckets for buckets).
func isComposite(group, res string) bool {
	if !strings.HasPrefix(res, "x") {
		return false
	}
	_, ok := byResource[group+"/"+strings.TrimPrefix(res, "x")]
	return ok
}

func (s Scope) operator(v Verb, group, res, sub, namespace, name string) string {
	kind := operatorKinds[res]
	if kind == "" {
		kind = camel(singular(res))
		if isComposite(group, res) {
			kind = "X" + byResource[group+"/"+strings.TrimPrefix(res, "x")].Kind
		}
	}
	noun := kind
	if v == List && sub == "" {
		noun = plural(kind)
	}
	if sub != "" {
		noun += camel(sub)
	}
	return OperatorPrefix + ":" + operatorVerb[v] + noun
}

func (s Scope) operatorARN(v Verb, res, namespace, name string) string {
	if v == List || name == "" {
		return "*"
	}
	path := res + "/" + name
	if namespace != "" {
		path = res + "/" + namespace + "/" + name
	}
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s", s.partition(), OperatorPrefix, s.region(), s.Account, path)
}

func singular(p string) string {
	switch {
	case strings.HasSuffix(p, "ies"):
		return strings.TrimSuffix(p, "ies") + "y"
	case strings.HasSuffix(p, "sses"), strings.HasSuffix(p, "ches"), strings.HasSuffix(p, "xes"):
		return strings.TrimSuffix(p, "es")
	case strings.HasSuffix(p, "s"):
		return strings.TrimSuffix(p, "s")
	}
	return p
}

func camel(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return b.String()
}
