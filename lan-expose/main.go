// lan-expose — open-infra's LAN-exposure controller. A single cluster-wide
// controller (deployed by platform/networking/lan-expose/) that watches Services
// annotated openinfra.dev/lan-expose: "true" and provisions the kube-ovn
// external-gateway chain (OvnEip + OvnFip + return-path VPC policyRoute) so the
// Service's pod is reachable from the physical LAN on a stable EIP — automating the
// hand-built recipe in memory kube-ovn-lan-exposure. Everything it touches is a CRD
// or the VPC CR, so it never has to exec into OVN.
//
// Env: POLL_INTERVAL (s, default 15), EXPOSE_ANNOTATION, IP_ANNOTATION,
// ASSIGNED_ANNOTATION, EXTERNAL_SUBNET, LAN_CIDR, EIP_RANGE, DEFAULT_VPC,
// POLICY_PRIORITY.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	poll := envInt("POLL_INTERVAL", 15)
	if poll <= 0 {
		poll = 15
	}

	// LAN_CIDR + EIP_RANGE are site-specific and must be supplied (the manifest
	// sources them from config.yaml). No default is baked in — this repo is public
	// and must not carry a real site's addressing. See memory
	// no-site-hostnames-in-public-manifests.
	lanCIDR := os.Getenv("LAN_CIDR")
	eipRangeStr := os.Getenv("EIP_RANGE")
	if lanCIDR == "" || eipRangeStr == "" {
		log.Fatalf("LAN_CIDR and EIP_RANGE are required (set them from config.yaml networking.lanExpose)")
	}
	rng, err := parseIPRange(eipRangeStr)
	if err != nil {
		log.Fatalf("EIP_RANGE: %v", err)
	}
	cfg := config{
		exposeAnno:     env("EXPOSE_ANNOTATION", "openinfra.dev/lan-expose"),
		ipAnno:         env("IP_ANNOTATION", "openinfra.dev/lan-ip"),
		assignedAnno:   env("ASSIGNED_ANNOTATION", "openinfra.dev/lan-ip-assigned"),
		externalSubnet: env("EXTERNAL_SUBNET", "external"),
		lanCIDR:        lanCIDR,
		defaultVPC:     env("DEFAULT_VPC", "ovn-cluster"),
		eipRange:       rng,
		policyPriority: envInt("POLICY_PRIORITY", 29500),
	}

	client, err := newInClusterClient()
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	ctrl := &controller{client: client, cfg: cfg}
	ticker := time.NewTicker(time.Duration(poll) * time.Second)
	defer ticker.Stop()

	log.Printf("lan-expose: watching Services[%s=true] cluster-wide; EIP range %s on subnet %q; polling every %ds",
		cfg.exposeAnno, eipRangeStr, cfg.externalSubnet, poll)
	ctrl.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			log.Printf("lan-expose: shutting down")
			return
		case <-ticker.C:
			ctrl.reconcile(ctx)
		}
	}
}
