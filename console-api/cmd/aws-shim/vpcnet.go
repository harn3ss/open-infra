// Lambda functions in a VPC (Lambda's VpcConfig): the network interfaces of their execution environments,
// shared by the VPC resolver (Route 53 Resolver: DNS Firewall and query logging), EC2's flow logs and
// DescribeNetworkInterfaces.
//
// A function with VpcConfig runs its execution environments on the platform's Lambda VPC subnet: the
// kube-ovn subnet LAMBDA_VPC_SUBNET (platform/networking/kube-ovn/lambda-vpc-subnet.yaml), which lets DNS
// reach only the VPC resolver. Its pods carry the label openinfra.dev/lambda-vpc and, from the function's
// VpcConfig, the annotations openinfra.dev/vpc-id, openinfra.dev/subnet-ids and
// openinfra.dev/security-group-ids (function-composition.yaml).
//
// An execution environment's network interface is the function's interface in one of its subnets, as on
// Lambda: one interface per function and subnet (eni-…, lambdaENIID), an environment placed in one of the
// function's subnets by its pod name. Its address is the pod's, from the Lambda VPC subnet, not from the
// subnet's CIDR (docs/lambda-vpc.md says so).
//
// vpcInterfaces follows the subnet's kube-ovn IP objects (one per pod address, labelled with the subnet):
// list and watch on ips.kubeovn.io, and get on pods for a new address's pod. It remembers an interface for
// a while after its pod is gone, so a flow-log record or a query that arrives late is still attributed to
// the function that sent it.
package main

import (
	"context"
	"hash/fnv"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	lambdaVPCLabel           = "openinfra.dev/lambda-vpc" // "true" on a VPC function's pods
	lambdaVPCIDAnnotation    = "openinfra.dev/vpc-id"
	lambdaSubnetsAnnotation  = "openinfra.dev/subnet-ids"         // comma-separated
	lambdaSGsAnnotation      = "openinfra.dev/security-group-ids" // comma-separated
	kubeovnSubnetLabel       = "ovn.kubernetes.io/subnet"
	defaultLambdaVPCSubnet   = "openinfra-lambda-vpc"
	vpcInterfaceKeep         = 30 * time.Minute // how long a detached interface is remembered
	vpcInterfaceAttachJitter = 30 * time.Second // allowance either side of an interface's lifetime
)

var kubeovnIPGVR = schema.GroupVersionResource{Group: "kubeovn.io", Version: "v1", Resource: "ips"}

// vpcInterface is one execution environment's network interface: its address and what it belongs to.
type vpcInterface struct {
	IP, Node                    string
	Namespace, Pod              string
	Account, Function           string
	VpcID, SubnetID             string
	SubnetIDs, SecurityGroupIDs []string
	ENI                         string
	MAC                         string    // the interface's MAC address (the IP object's spec.macAddress)
	Attached, Detached          time.Time // Detached is zero while the pod runs
}

// lambdaENIID is the id of the network interface Lambda gives function in subnet (one per function and
// subnet), the shape every other EC2 id here takes (shortHashID).
func lambdaENIID(account, function, subnet string) string {
	return shortHashID("eni-", account+"/"+function+"/"+subnet, 17)
}

// subnetOf is the subnet an execution environment is placed in: one of its function's, spread by pod name.
func subnetOf(pod string, subnets []string) string {
	if len(subnets) == 0 {
		return ""
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(pod))
	return subnets[int(h.Sum32()%uint32(len(subnets)))]
}

// splitIDs is a comma-separated annotation's ids, trimmed, empties dropped.
func splitIDs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// interfaceForPod is the interface of a VPC function's pod at ip; false for a pod that is not one.
func interfaceForPod(pod *corev1.Pod, ip, node, account string, at time.Time) (vpcInterface, bool) {
	if pod == nil || pod.Labels[lambdaVPCLabel] != "true" {
		return vpcInterface{}, false
	}
	fn := pod.Labels[knativeServiceLabel]
	vpc := pod.Annotations[lambdaVPCIDAnnotation]
	subnets := splitIDs(pod.Annotations[lambdaSubnetsAnnotation])
	if fn == "" || vpc == "" || len(subnets) == 0 {
		return vpcInterface{}, false
	}
	subnet := subnetOf(pod.Name, subnets)
	return vpcInterface{IP: ip, Node: node, Namespace: pod.Namespace, Pod: pod.Name, Account: account, Function: fn,
		VpcID: vpc, SubnetID: subnet, SubnetIDs: subnets, SecurityGroupIDs: splitIDs(pod.Annotations[lambdaSGsAnnotation]),
		ENI: lambdaENIID(account, fn, subnet), Attached: at}, true
}

// podGetter reads one pod (get on pods).
func podGetter(cs kubernetes.Interface) func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
		return cs.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	}
}

// vpcInterfaces is the Lambda VPC subnet's interfaces by address, current and recently detached.
type vpcInterfaces struct {
	dyn       dynamic.Interface
	getPod    func(ctx context.Context, namespace, name string) (*corev1.Pod, error)
	accountOf func(namespace string) string
	subnet    string
	logger    *slog.Logger
	now       func() time.Time

	mu    sync.RWMutex
	byIP  map[string][]vpcInterface // oldest first
	byObj map[string]string         // kube-ovn IP object name -> address
	ready bool
}

func newVPCInterfaces(dyn dynamic.Interface, getPod func(ctx context.Context, namespace, name string) (*corev1.Pod, error),
	accountOf func(string) string, subnet string, logger *slog.Logger) *vpcInterfaces {
	if subnet == "" {
		subnet = defaultLambdaVPCSubnet
	}
	return &vpcInterfaces{dyn: dyn, getPod: getPod, accountOf: accountOf, subnet: subnet, logger: logger, now: time.Now,
		byIP: map[string][]vpcInterface{}, byObj: map[string]string{}}
}

// At is the interface that had ip at t (the newest, when an address was reused within the allowance).
func (v *vpcInterfaces) At(ip string, t time.Time) (vpcInterface, bool) {
	if v == nil {
		return vpcInterface{}, false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	hist := v.byIP[ip]
	for i := len(hist) - 1; i >= 0; i-- {
		in := hist[i]
		if t.Before(in.Attached.Add(-vpcInterfaceAttachJitter)) {
			continue
		}
		if !in.Detached.IsZero() && t.After(in.Detached.Add(vpcInterfaceAttachJitter)) {
			continue
		}
		return in, true
	}
	return vpcInterface{}, false
}

// Current is every attached interface, ordered by account, function and address.
func (v *vpcInterfaces) Current() []vpcInterface {
	if v == nil {
		return nil
	}
	v.mu.RLock()
	var out []vpcInterface
	for _, hist := range v.byIP {
		if n := len(hist); n > 0 && hist[n-1].Detached.IsZero() {
			out = append(out, hist[n-1])
		}
	}
	v.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Account != out[j].Account {
			return out[i].Account < out[j].Account
		}
		if out[i].Function != out[j].Function {
			return out[i].Function < out[j].Function
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// Ready reports whether the first listing has been taken.
func (v *vpcInterfaces) Ready() bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.ready
}

// attach records the interface of the pod an IP object names (once per object and address).
func (v *vpcInterfaces) attach(ctx context.Context, obj *unstructured.Unstructured) {
	name := obj.GetName()
	ip, _, _ := unstructured.NestedString(obj.Object, "spec", "ipAddress")
	if ip == "" {
		ip, _, _ = unstructured.NestedString(obj.Object, "spec", "v4IpAddress")
	}
	ns, _, _ := unstructured.NestedString(obj.Object, "spec", "namespace")
	podName, _, _ := unstructured.NestedString(obj.Object, "spec", "podName")
	node, _, _ := unstructured.NestedString(obj.Object, "spec", "nodeName")
	if ip == "" || ns == "" || podName == "" {
		return
	}
	v.mu.RLock()
	known := v.byObj[name] == ip
	v.mu.RUnlock()
	if known {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	pod, err := v.getPod(pctx, ns, podName)
	cancel()
	if err != nil {
		if v.logger != nil {
			v.logger.Debug("lambda vpc: the pod of an address could not be read", slog.String("error", err.Error()))
		}
		return
	}
	account := ""
	if v.accountOf != nil {
		account = v.accountOf(ns)
	}
	at := obj.GetCreationTimestamp().Time
	if at.IsZero() {
		at = v.now()
	}
	in, ok := interfaceForPod(pod, ip, node, account, at)
	if !ok {
		return
	}
	in.MAC, _, _ = unstructured.NestedString(obj.Object, "spec", "macAddress")
	v.mu.Lock()
	v.byObj[name] = ip
	v.byIP[ip] = append(v.byIP[ip], in)
	v.mu.Unlock()
}

// detach marks the interface an IP object named as gone, and forgets interfaces detached long ago.
func (v *vpcInterfaces) detach(name string) {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	ip, ok := v.byObj[name]
	if ok {
		delete(v.byObj, name)
		if hist := v.byIP[ip]; len(hist) > 0 && hist[len(hist)-1].Detached.IsZero() {
			hist[len(hist)-1].Detached = now
		}
	}
	v.pruneLocked(now)
}

func (v *vpcInterfaces) pruneLocked(now time.Time) {
	for ip, hist := range v.byIP {
		keep := hist[:0]
		for _, in := range hist {
			if in.Detached.IsZero() || now.Sub(in.Detached) < vpcInterfaceKeep {
				keep = append(keep, in)
			}
		}
		if len(keep) == 0 {
			delete(v.byIP, ip)
		} else {
			v.byIP[ip] = keep
		}
	}
}

// Run follows the subnet's IP objects until ctx ends: a listing, then a watch, re-listing whenever the watch
// breaks in a way that may have lost events. An object a re-listing no longer shows is detached.
func (v *vpcInterfaces) Run(ctx context.Context) {
	if v == nil || v.dyn == nil {
		return
	}
	sel := kubeovnSubnetLabel + "=" + v.subnet
	rv := ""
	for ctx.Err() == nil {
		if rv == "" {
			l, err := v.dyn.Resource(kubeovnIPGVR).List(ctx, metav1.ListOptions{LabelSelector: sel})
			if err != nil {
				if v.logger != nil {
					v.logger.Warn("lambda vpc: the subnet's addresses could not be listed", slog.String("subnet", v.subnet), slog.String("error", err.Error()))
				}
				sleepCtx(ctx, 10*time.Second)
				continue
			}
			seen := map[string]bool{}
			for i := range l.Items {
				seen[l.Items[i].GetName()] = true
				v.attach(ctx, &l.Items[i])
			}
			v.mu.RLock()
			var gone []string
			for name := range v.byObj {
				if !seen[name] {
					gone = append(gone, name)
				}
			}
			v.mu.RUnlock()
			for _, name := range gone {
				v.detach(name)
			}
			v.mu.Lock()
			v.ready = true
			v.mu.Unlock()
			rv = l.GetResourceVersion()
		}
		rv = v.follow(ctx, sel, rv)
	}
}

func (v *vpcInterfaces) follow(ctx context.Context, sel, rv string) string {
	w, err := v.dyn.Resource(kubeovnIPGVR).Watch(ctx, metav1.ListOptions{LabelSelector: sel, ResourceVersion: rv, AllowWatchBookmarks: true})
	if err != nil {
		sleepCtx(ctx, 2*time.Second)
		return ""
	}
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return rv
		case ev, ok := <-w.ResultChan():
			if !ok {
				return rv
			}
			obj, isObj := ev.Object.(*unstructured.Unstructured)
			switch ev.Type {
			case watch.Added, watch.Modified:
				if isObj {
					v.attach(ctx, obj)
				}
			case watch.Deleted:
				if isObj {
					v.detach(obj.GetName())
				}
			case watch.Bookmark:
			case watch.Error:
				return ""
			}
			if isObj && obj.GetResourceVersion() != "" {
				rv = obj.GetResourceVersion()
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// deliver writes events (oldest first) to stream of account's log group, creating the group and the stream
// when they are missing, as AWS's own log delivery (VPC Flow Logs, Resolver query logging) does. group is
// the group's name; the store key is the account's (accountKeyFor).
func (s *cwlStore) deliver(ctx context.Context, account, region, group, stream string, events []putEvent) error {
	if s == nil || len(events) == 0 {
		return nil
	}
	key := accountKeyFor(account, group)
	arn := "arn:aws:logs:" + region + ":" + account + ":log-group:" + group + ":*"
	if _, err := s.createGroup(ctx, key, arn, nil); err != nil {
		return err
	}
	if _, _, err := s.createStream(ctx, key, stream); err != nil {
		return err
	}
	return s.putEvents(ctx, key, stream, events, time.Now().UnixMilli())
}

// logGroupOfARN is the account and name of a CloudWatch Logs log group ARN
// (arn:aws:logs:<region>:<account>:log-group:<name>[:*]); ok false for anything else.
func logGroupOfARN(arn string) (account, name string, ok bool) {
	p := strings.SplitN(arn, ":", 7)
	if len(p) != 7 || p[0] != "arn" || p[2] != "logs" || !strings.HasPrefix(p[5], "log-group") {
		return "", "", false
	}
	// p[5] is "log-group" and p[6] the name (and an optional ":*").
	if p[5] != "log-group" {
		return "", "", false
	}
	name = strings.TrimSuffix(p[6], ":*")
	if name == "" || strings.Contains(name, ":") {
		return "", "", false
	}
	return p[4], name, true
}
