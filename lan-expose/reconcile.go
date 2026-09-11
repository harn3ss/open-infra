// The lan-expose reconcile: for every Service annotated openinfra.dev/lan-expose:
// "true", provision the kube-ovn external-gateway chain so the Service's pod is
// reachable from the LAN on a stable EIP — an OvnEip + OvnFip (dnat_and_snat, which
// unlike a port-forward LB VIP is ARP-reachable to same-subnet clients) plus the
// return-path policyRoute that stops the subnet's natOutgoing from hijacking the
// reply. See memory kube-ovn-lan-exposure for the mechanism this automates.
//
// Model (v1, single-endpoint): named deterministically as lanexpose-<ns>-<svc>, so
// the loop is idempotent. The FIP is re-pointed when the backing pod changes, and
// the whole chain is torn down when the annotation/Service goes away.
package main

import (
	"context"
	"log"
	"strings"
)

type config struct {
	exposeAnno     string // Service annotation that opts a Service in ("true")
	ipAnno         string // optional annotation requesting a specific EIP
	assignedAnno   string // annotation we write back with the assigned EIP
	externalSubnet string // kube-ovn external Subnet name (default "external")
	lanCIDR        string // the LAN /24 the EIPs live on
	defaultVPC     string // the default VPC router name (ovn-cluster)
	eipRange       ipRange
	policyPriority int
}

type controller struct {
	client *k8sClient
	cfg    config
}

const managedPrefix = "lanexpose-"

// reconcile runs one full sweep. It is level-triggered and safe to run every poll;
// changes converge over one or two polls (e.g. a re-point that must wait for a delete).
func (c *controller) reconcile(ctx context.Context) {
	services, err := c.client.listServices(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("list services: %v", err)
		}
		return
	}
	eips, err := c.client.listOvnEips(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("list ovn-eips: %v", err)
		}
		return
	}

	// Every EIP already in use (ours or otherwise) is off-limits for auto-allocation.
	used := map[string]bool{}
	for _, e := range eips {
		for _, ip := range []string{e.Spec.V4Ip, e.Status.V4Ip} {
			if ip != "" {
				used[ip] = true
			}
		}
	}

	wantResource := map[string]bool{} // lanexpose-* names we should keep
	var wantPodIPs []string

	for i := range services {
		s := services[i]
		if strings.ToLower(s.Metadata.Annotations[c.cfg.exposeAnno]) != "true" {
			continue
		}
		ns, name := s.Metadata.Namespace, s.Metadata.Name
		rn := resourceName(ns, name)

		pod := c.pickEndpoint(ctx, s)
		if pod == nil {
			log.Printf("%s/%s: no Running pod with an IP yet, waiting", ns, name)
			continue
		}

		eip, ok := c.ensureEip(ctx, rn, s, eips, used)
		if !ok {
			continue
		}
		used[eip] = true

		if !c.ensureFip(ctx, rn, pod) {
			continue
		}

		wantResource[rn] = true
		wantPodIPs = append(wantPodIPs, pod.Status.PodIP)

		if err := c.ensureNetpol(ctx, rn, ns, s.Spec.Selector); err != nil {
			log.Printf("%s/%s: ensure LAN netpol: %v", ns, name, err)
		}

		if s.Metadata.Annotations[c.cfg.assignedAnno] != eip {
			if err := c.client.patchServiceAnnotations(ctx, ns, name, map[string]string{c.cfg.assignedAnno: eip}); err != nil {
				log.Printf("%s/%s: publish assigned EIP: %v", ns, name, err)
			}
		}
		log.Printf("%s/%s: exposed on %s -> pod %s (%s)", ns, name, eip, pod.Metadata.Name, pod.Status.PodIP)
	}

	c.gc(ctx, eips, wantResource)
	c.reconcilePolicy(ctx, wantPodIPs)
}

// pickEndpoint resolves the Service's backing pod: the first Running pod (matching the
// selector) that has an IP. v1 targets a single endpoint.
func (c *controller) pickEndpoint(ctx context.Context, s Service) *Pod {
	pods, err := c.client.listPods(ctx, s.Metadata.Namespace, s.Spec.Selector)
	if err != nil {
		log.Printf("%s/%s: list pods: %v", s.Metadata.Namespace, s.Metadata.Name, err)
		return nil
	}
	for i := range pods {
		if pods[i].Status.Phase == "Running" && pods[i].Status.PodIP != "" {
			return &pods[i]
		}
	}
	return nil
}

// ensureEip returns the EIP for a Service, creating the OvnEip if needed. Priority:
// explicit openinfra.dev/lan-ip annotation, else the EIP already bound to our OvnEip,
// else a fresh allocation from the configured range.
func (c *controller) ensureEip(ctx context.Context, rn string, s Service, eips []OvnEip, used map[string]bool) (string, bool) {
	ns, name := s.Metadata.Namespace, s.Metadata.Name
	existing, _, err := c.client.getOvnEip(ctx, rn)
	if err != nil {
		log.Printf("%s/%s: get eip: %v", ns, name, err)
		return "", false
	}

	eip := strings.TrimSpace(s.Metadata.Annotations[c.cfg.ipAnno])
	switch {
	case eip != "":
		// explicit request — honour it
	case existing != nil && existing.Spec.V4Ip != "":
		eip = existing.Spec.V4Ip // keep what we already gave it (stable)
	default:
		// allocate the lowest free IP in range, not counting our own current one
		free := c.cfg.eipRange.allocate(used)
		if free == "" {
			log.Printf("%s/%s: EIP range exhausted, cannot expose", ns, name)
			return "", false
		}
		eip = free
	}

	if existing != nil && existing.Spec.V4Ip != eip {
		// the desired IP changed (annotation edited); recreate cleanly next poll
		log.Printf("%s/%s: EIP change %s -> %s, recreating", ns, name, existing.Spec.V4Ip, eip)
		_ = c.client.deleteOvnFip(ctx, rn)
		_ = c.client.deleteOvnEip(ctx, rn)
		return "", false
	}
	if existing == nil {
		if err := c.client.createOvnEip(ctx, rn, c.cfg.externalSubnet, eip); err != nil {
			log.Printf("%s/%s: create eip %s: %v", ns, name, eip, err)
			return "", false
		}
	}
	return eip, true
}

// ensureFip makes the OvnFip point at the current pod. A v4Ip FIP does not reliably
// program the NAT, so we always target by ipName (<pod>.<ns>) and re-point on change.
func (c *controller) ensureFip(ctx context.Context, rn string, pod *Pod) bool {
	wantIPName := pod.Metadata.Name + "." + pod.Metadata.Namespace
	fip, _, err := c.client.getOvnFip(ctx, rn)
	if err != nil {
		log.Printf("%s: get fip: %v", rn, err)
		return false
	}
	if fip == nil {
		if err := c.client.createOvnFip(ctx, rn, rn, wantIPName); err != nil {
			log.Printf("%s: create fip -> %s: %v", rn, wantIPName, err)
			return false
		}
		return true
	}
	if fip.Spec.IPName != wantIPName {
		// Patching spec.ipName does NOT make kube-ovn re-program the NAT (it stays
		// bound to the old, now-deleted pod). The only reliable re-point is to
		// delete and let a subsequent poll recreate the FIP for the current pod,
		// which programs a fresh NAT with the new pod's MAC. Costs ~one poll of
		// downtime on a pod restart.
		log.Printf("%s: backing pod changed (%s -> %s), recreating FIP", rn, fip.Spec.IPName, wantIPName)
		if err := c.client.deleteOvnFip(ctx, rn); err != nil {
			log.Printf("%s: delete fip for re-point: %v", rn, err)
		}
		return false
	}
	return true
}

// ensureNetpol adds the additive ipBlock-allow NetworkPolicy for a service's pods so
// the FIP-preserved LAN client IP isn't dropped by the app's default-deny policy.
func (c *controller) ensureNetpol(ctx context.Context, rn, ns string, selector map[string]string) error {
	if len(selector) == 0 {
		return nil
	}
	exists, err := c.client.getNetworkPolicy(ctx, ns, rn)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return c.client.createLanNetpol(ctx, ns, rn, selector, c.cfg.lanCIDR)
}

// gc removes the OvnEip/OvnFip pairs and NetworkPolicies we own whose Service is no
// longer exposed.
func (c *controller) gc(ctx context.Context, eips []OvnEip, keep map[string]bool) {
	for _, e := range eips {
		n := e.Metadata.Name
		if !strings.HasPrefix(n, managedPrefix) || keep[n] {
			continue
		}
		log.Printf("gc: tearing down %s (no longer exposed)", n)
		_ = c.client.deleteOvnFip(ctx, n)
		_ = c.client.deleteOvnEip(ctx, n)
	}
	nps, err := c.client.listManagedNetpols(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("list managed netpols: %v", err)
		}
		return
	}
	for _, np := range nps {
		if !strings.HasPrefix(np.Metadata.Name, managedPrefix) || keep[np.Metadata.Name] {
			continue
		}
		log.Printf("gc: removing LAN netpol %s/%s", np.Metadata.Namespace, np.Metadata.Name)
		_ = c.client.deleteNetworkPolicy(ctx, np.Metadata.Namespace, np.Metadata.Name)
	}
}

// reconcilePolicy folds the wanted pod IPs into the default VPC's policyRoutes,
// preserving any foreign entries and patching only when something changed.
func (c *controller) reconcilePolicy(ctx context.Context, wantPodIPs []string) {
	vpc, err := c.client.getVpc(ctx, c.cfg.defaultVPC)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("get vpc %s: %v", c.cfg.defaultVPC, err)
		}
		return
	}
	desired := mergePolicyRoutes(vpc.Spec.PolicyRoutes, wantPodIPs, c.cfg.policyPriority, c.cfg.lanCIDR)
	if policyRoutesEqual(sortRoutes(vpc.Spec.PolicyRoutes), desired) {
		return
	}
	log.Printf("policyRoutes: updating (%d entries) for %d exposed pod(s)", len(desired), len(wantPodIPs))
	if err := c.client.patchVpcPolicyRoutes(ctx, c.cfg.defaultVPC, desired); err != nil {
		log.Printf("patch vpc policyRoutes: %v", err)
	}
}
