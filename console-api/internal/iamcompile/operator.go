package iamcompile

// operatorResource is one raw Kubernetes resource of the operator's surface (the console's operator
// pages), compiled per resource. Its IAM action is awsaction.ForKubernetes's openinfra-operator:<Verb><Kind>.
type operatorResource struct {
	Group, Resource string
	Namespaced      bool
}

// operatorResources is the operator surface the compiler grants per resource. A principal whose policies
// grant a verb on EVERYTHING — every table kind, every resource here and the rest of the operator surface
// — gets that verb as a wildcard instead (wildcardVerb), which also covers other groups' CRDs.
var operatorResources = []operatorResource{
	{"", "pods", true}, {"", "pods/log", true}, {"", "services", true}, {"", "endpoints", true},
	{"", "events", true}, {"", "configmaps", true}, {"", "secrets", true}, {"", "persistentvolumeclaims", true},
	{"", "serviceaccounts", true}, {"", "resourcequotas", true}, {"", "limitranges", true},
	{"apps", "deployments", true}, {"apps", "statefulsets", true}, {"apps", "daemonsets", true}, {"apps", "replicasets", true},
	{"batch", "jobs", true}, {"batch", "cronjobs", true},
	{"networking.k8s.io", "ingresses", true}, {"networking.k8s.io", "networkpolicies", true},
	{"autoscaling", "horizontalpodautoscalers", true}, {"policy", "poddisruptionbudgets", true},
	{"rbac.authorization.k8s.io", "roles", true}, {"rbac.authorization.k8s.io", "rolebindings", true},
	{"", "nodes", false}, {"", "namespaces", false}, {"", "persistentvolumes", false},
	{"storage.k8s.io", "storageclasses", false}, {"apiextensions.k8s.io", "customresourcedefinitions", false},
	{"rbac.authorization.k8s.io", "clusterroles", false}, {"rbac.authorization.k8s.io", "clusterrolebindings", false},
}

// sentinelOperator stands for "the rest of the operator surface" (another group's CRD) when deciding
// whether a principal's policies grant a verb on everything.
var sentinelOperator = operatorResource{"example.openinfra.invalid", "widgets", true}

// discoveryPaths are the API server's discovery endpoints: plumbing every Kubernetes client reads
// before it acts, not an AWS action. A principal with any compiled grant may read them (the
// system:discovery role's paths), so the iam-corpus, which is authoritative for it, does not break
// its clients; a principal with none gets nothing, as on AWS.
var discoveryPaths = []string{"/api", "/api/*", "/apis", "/apis/*", "/version", "/version/", "/openapi/*", "/healthz", "/livez", "/readyz"}
