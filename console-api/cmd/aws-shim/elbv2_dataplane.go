package main

// A network load balancer's traffic (elbv2.go): each load balancer is a LoadBalancer Service in the shim's
// namespace, without a selector, whose ports are its listeners'; each listener's targets are EndpointSlices
// the shim writes, one per target port, carrying the address and node of every registered instance that is
// running. The Service keeps the client's address (externalTrafficPolicy Local: the address is announced from
// the nodes the targets run on), so a target's security groups see, and decide on, the client itself. The
// Service takes its address from the installation's load-balancer address pool (ELB_ADDRESS_POOL), and opens
// no node ports.
//
// A pass over every account's load balancers (run) keeps the endpoints current as instances stop, start and
// move between nodes, removes a terminated instance from its target groups (AWS deregisters it), and removes
// the objects of a load balancer that is gone, or of an account whose home is.

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	elbPoolAnnotation = "metallb.universe.tf/address-pool"
	elbManagedBy      = "aws-shim.openinfra.dev"
	elbHolderPort     = 9 // the one port a load balancer without listeners declares (UDP discard): it has no endpoints
)

func elbServiceName(account, lb string) string { return "elb-" + account + "-" + lb }

// elbSliceName is the EndpointSlice of a listener's targets on targetPort, for protocol proto.
func elbSliceName(svc, proto string, listenerPort, targetPort int) string {
	return svc + "-" + strings.ToLower(proto) + strconv.Itoa(listenerPort) + "-" + strconv.Itoa(targetPort)
}

func elbPortName(proto string, port int) string {
	return strings.ToLower(proto) + "-" + strconv.Itoa(port)
}

// elbProtocols are the transport protocols a listener protocol carries.
func elbProtocols(p string) []corev1.Protocol {
	switch p {
	case "UDP":
		return []corev1.Protocol{corev1.ProtocolUDP}
	case "TCP_UDP":
		return []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP}
	}
	return []corev1.Protocol{corev1.ProtocolTCP}
}

// addresses are account's load balancers' addresses, by load balancer id (one not yet assigned is absent).
func (h *elbHandler) addresses(ctx context.Context, account string) map[string]string {
	out := map[string]string{}
	l, err := h.cs.CoreV1().Services(h.ns).List(ctx, metav1.ListOptions{LabelSelector: elbAccountLabel + "=" + account})
	if err != nil {
		return out
	}
	for _, s := range l.Items {
		if ing := s.Status.LoadBalancer.Ingress; len(ing) > 0 && ing[0].IP != "" {
			out[s.Labels[elbLBLabel]] = ing[0].IP
		}
	}
	return out
}

// elbEndpoint is where a running instance receives its traffic: its address and its node.
type elbEndpoint struct{ ip, node string }

// endpointOf reads in's endpoint from its VirtualMachineInstance (none while it is not running).
func (h *elbHandler) endpointOf(ctx context.Context, in *ec2Instance) elbEndpoint {
	if in == nil || in.claim == nil || h.ec2.door.shimDyn == nil {
		return elbEndpoint{}
	}
	vmi, err := h.ec2.door.shimDyn.Resource(vmiGVR).Namespace(in.claim.GetNamespace()).Get(ctx, in.claim.GetName(), metav1.GetOptions{})
	if err != nil {
		return elbEndpoint{}
	}
	if phase, _, _ := unstructured.NestedString(vmi.Object, "status", "phase"); phase != "Running" {
		return elbEndpoint{}
	}
	node, _, _ := unstructured.NestedString(vmi.Object, "status", "nodeName")
	ifaces, _, _ := unstructured.NestedSlice(vmi.Object, "status", "interfaces")
	for _, i := range ifaces {
		m, _ := i.(map[string]any)
		if ip, _ := m["ipAddress"].(string); ip != "" && !strings.Contains(ip, ":") && node != "" {
			return elbEndpoint{ip: ip, node: node}
		}
	}
	return elbEndpoint{}
}

// accountContext is ctx acting in account (whose home is ns), as a request in it would.
func accountContext(ctx context.Context, account, ns string) context.Context {
	if awsidentity.Current().IsManagement(account) {
		return ctx
	}
	return awsidentity.WithIdentity(withAccountHome(ctx, ns), awsidentity.Current().ForAccount(account, ns))
}

// instancesIn are the instances of rec's account, by id (ok false when they could not be read).
func (h *elbHandler) instancesIn(ctx context.Context, rec *elbRecords) (map[string]*ec2Instance, bool) {
	if rec.Namespace == "" || h.ec2.door.shimDyn == nil {
		return nil, false
	}
	l, err := h.ec2.door.shimDyn.Resource(vmClaimGVR).Namespace(rec.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, false
	}
	actx := accountContext(ctx, rec.Account, rec.Namespace)
	out := map[string]*ec2Instance{}
	for i := range l.Items {
		in := h.ec2.instanceOf(actx, &l.Items[i], nil)
		out[in.id] = &in
	}
	return out, true
}

// sync brings rec's load balancers' Services and EndpointSlices in line with its records.
func (h *elbHandler) sync(ctx context.Context, rec *elbRecords) error {
	insts, listed := h.instancesIn(ctx, rec)
	var errs []error
	wantSvc, wantSlice := map[string]bool{}, map[string]bool{}
	var gone []elbTarget
	goneSeen := map[elbTarget]bool{}
	for _, lb := range rec.LoadBalancers {
		svc := elbServiceName(rec.Account, lb.ID)
		wantSvc[svc] = true
		listeners := rec.listenersOf(lb.ID)
		if err := h.applyService(ctx, rec.Account, lb.ID, svc, listeners); err != nil {
			errs = append(errs, err)
		}
		for _, l := range listeners {
			g := rec.tg(l.TargetGroup)
			if g == nil {
				continue
			}
			byPort := map[int][]discoveryv1.Endpoint{}
			var ports []int
			for _, t := range g.Targets {
				if _, ok := byPort[t.Port]; !ok {
					byPort[t.Port] = []discoveryv1.Endpoint{}
					ports = append(ports, t.Port)
				}
				in := insts[t.ID]
				if in == nil {
					if listed && !goneSeen[t] {
						goneSeen[t] = true
						gone = append(gone, t)
					}
					continue
				}
				if in.state != "running" {
					continue
				}
				ep := h.endpointOf(ctx, in)
				if ep.ip == "" {
					continue
				}
				node := ep.node
				byPort[t.Port] = append(byPort[t.Port], discoveryv1.Endpoint{Addresses: []string{ep.ip}, NodeName: &node,
					Conditions: discoveryv1.EndpointConditions{Ready: ptrTo(true), Serving: ptrTo(true), Terminating: ptrTo(false)}})
			}
			sort.Ints(ports)
			for _, proto := range elbProtocols(l.Protocol) {
				for _, p := range ports {
					name := elbSliceName(svc, string(proto), l.Port, p)
					wantSlice[name] = true
					if err := h.applySlice(ctx, rec.Account, lb.ID, svc, name, elbPortName(string(proto), l.Port), proto, p, byPort[p]); err != nil {
						errs = append(errs, err)
					}
				}
			}
		}
	}
	errs = append(errs, h.prune(ctx, rec.Account, wantSvc, wantSlice))
	// A terminated instance leaves its target groups, as AWS deregisters it.
	if len(gone) > 0 {
		if _, err := h.update(ctx, rec.Account, "", func(r *elbRecords) error {
			drop := map[string]bool{}
			for _, t := range gone {
				drop[t.ID] = true
			}
			for _, g := range r.TargetGroups {
				g.Targets = removeWhere(g.Targets, func(t elbTarget) bool { return drop[t.ID] })
			}
			return nil
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func ptrTo[T any](v T) *T { return &v }

// applyService creates or updates load balancer lb's Service: its listeners' ports, the client's address
// kept, no node ports, its address from the pool.
func (h *elbHandler) applyService(ctx context.Context, account, lb, name string, listeners []*elbListener) error {
	var ports []corev1.ServicePort
	for _, l := range listeners {
		for _, proto := range elbProtocols(l.Protocol) {
			ports = append(ports, corev1.ServicePort{Name: elbPortName(string(proto), l.Port), Protocol: proto, Port: int32(l.Port)})
		}
	}
	if len(ports) == 0 {
		ports = []corev1.ServicePort{{Name: "holder", Protocol: corev1.ProtocolUDP, Port: elbHolderPort}}
	}
	labels := map[string]string{elbAccountLabel: account, elbLBLabel: lb, "app.kubernetes.io/managed-by": elbManagedBy}
	svcs := h.cs.CoreV1().Services(h.ns)
	cur, err := svcs.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		s := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.ns, Labels: labels},
			Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
				AllocateLoadBalancerNodePorts: ptrTo(false), Ports: ports}}
		if h.pool != "" {
			s.Annotations = map[string]string{elbPoolAnnotation: h.pool}
		}
		_, err = svcs.Create(ctx, s, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	type portKey struct {
		name  string
		proto corev1.Protocol
		port  int32
	}
	key := func(ps []corev1.ServicePort) []portKey {
		out := make([]portKey, 0, len(ps))
		for _, p := range ps {
			out = append(out, portKey{p.Name, p.Protocol, p.Port})
		}
		return out
	}
	if reflect.DeepEqual(key(cur.Spec.Ports), key(ports)) && cur.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
		return nil
	}
	cur.Spec.Ports = ports
	cur.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	for k, v := range labels {
		if cur.Labels == nil {
			cur.Labels = map[string]string{}
		}
		cur.Labels[k] = v
	}
	_, err = svcs.Update(ctx, cur, metav1.UpdateOptions{})
	return err
}

// applySlice creates or updates the EndpointSlice name: a listener's targets on port, for proto.
func (h *elbHandler) applySlice(ctx context.Context, account, lb, svc, name, portName string, proto corev1.Protocol, port int, eps []discoveryv1.Endpoint) error {
	sort.Slice(eps, func(i, j int) bool { return eps[i].Addresses[0] < eps[j].Addresses[0] })
	p32 := int32(port)
	want := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.ns, Labels: map[string]string{
			discoveryv1.LabelServiceName: svc, discoveryv1.LabelManagedBy: elbManagedBy, elbAccountLabel: account, elbLBLabel: lb}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: &portName, Protocol: &proto, Port: &p32}},
		Endpoints:   eps,
	}
	slices := h.cs.DiscoveryV1().EndpointSlices(h.ns)
	cur, err := slices.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = slices.Create(ctx, &want, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if reflect.DeepEqual(cur.Ports, want.Ports) && reflect.DeepEqual(cur.Endpoints, want.Endpoints) && cur.Labels[discoveryv1.LabelServiceName] == svc {
		return nil
	}
	cur.Ports, cur.Endpoints, cur.AddressType = want.Ports, want.Endpoints, want.AddressType
	cur.Labels = want.Labels
	_, err = slices.Update(ctx, cur, metav1.UpdateOptions{})
	return err
}

// prune deletes account's Services and EndpointSlices that no load balancer or listener has any more.
func (h *elbHandler) prune(ctx context.Context, account string, wantSvc, wantSlice map[string]bool) error {
	sel := metav1.ListOptions{LabelSelector: elbAccountLabel + "=" + account}
	var errs []error
	if l, err := h.cs.DiscoveryV1().EndpointSlices(h.ns).List(ctx, sel); err != nil {
		errs = append(errs, err)
	} else {
		for _, s := range l.Items {
			if !wantSlice[s.Name] {
				if err := h.cs.DiscoveryV1().EndpointSlices(h.ns).Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
					errs = append(errs, err)
				}
			}
		}
	}
	if l, err := h.cs.CoreV1().Services(h.ns).List(ctx, sel); err != nil {
		errs = append(errs, err)
	} else {
		for _, s := range l.Items {
			if !wantSvc[s.Name] {
				if err := h.cs.CoreV1().Services(h.ns).Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// syncAll is one pass over every account's load balancers. The records of an account whose home namespace
// is gone are removed, and its load balancers with them.
func (h *elbHandler) syncAll(ctx context.Context) {
	l, err := h.cs.CoreV1().Secrets(h.ns).List(ctx, metav1.ListOptions{LabelSelector: elbRecordsLabel + "=records"})
	if err != nil {
		h.logger.Warn("elasticloadbalancing: the load balancer records could not be listed", "error", err.Error())
		return
	}
	have := map[string]bool{}
	for _, s := range l.Items {
		account := s.Labels[elbAccountLabel]
		if account == "" {
			continue
		}
		rec, _, lerr := h.load(ctx, account)
		if lerr != nil {
			h.logger.Warn("elasticloadbalancing: an account's load balancer records do not read", "account", account, "error", lerr.Error())
			continue
		}
		if rec.Namespace != "" {
			if _, nerr := h.cs.CoreV1().Namespaces().Get(ctx, rec.Namespace, metav1.GetOptions{}); apierrors.IsNotFound(nerr) {
				h.logger.Info("elasticloadbalancing: the account's home is gone; its load balancers are removed", "account", account)
				_ = h.cs.CoreV1().Secrets(h.ns).Delete(ctx, s.Name, metav1.DeleteOptions{})
				_ = h.prune(ctx, account, nil, nil)
				continue
			}
		}
		have[account] = true
		if serr := h.sync(ctx, rec); serr != nil {
			h.logger.Warn("elasticloadbalancing: an account's load balancers are not yet in line", "account", account, "error", serr.Error())
		}
	}
	// Objects of an account with no records left.
	svcs, err := h.cs.CoreV1().Services(h.ns).List(ctx, metav1.ListOptions{LabelSelector: elbAccountLabel})
	if err == nil {
		orphans := map[string]bool{}
		for _, s := range svcs.Items {
			if a := s.Labels[elbAccountLabel]; !have[a] {
				orphans[a] = true
			}
		}
		for a := range orphans {
			_ = h.prune(ctx, a, nil, nil)
		}
	}
}

// run keeps every account's load balancers in line, every interval, until ctx ends.
func (h *elbHandler) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		h.syncAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
