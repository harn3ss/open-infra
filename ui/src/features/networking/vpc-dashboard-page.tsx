import { Link } from "@tanstack/react-router";
import {
  GitBranch,
  LayoutGrid,
  ListChecks,
  Map as MapIcon,
  Milestone,
  Network,
  Plus,
  Route,
  ScrollText,
  Share2,
  Shield,
  Waypoints,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { StatCard } from "@/features/dashboard/stat-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import type {
  Condition,
  ElasticIp,
  FlowLog,
  NatGateway,
  SecurityGroup,
  Subnet,
  TransitGateway,
  Vpc,
} from "@/types/k8s";

// The resource-map route is registered by the integration pass (Unit A's other
// route). Typed as a plain string so it resolves via <Link> before then.
const RESOURCE_MAP_PATH: string = "/networking/map";

const isReady = (conditions?: Condition[]) =>
  conditions?.some((c) => c.type === "Ready" && c.status === "True") ?? false;

/**
 * The Networking section landing page — the AWS "VPC dashboard": resource-count
 * tiles that deep-link to each list, plus the primary Create VPC + Resource map
 * entry points. All counts are live via `useK8sWatch`; derived tiles (route
 * tables, peering, network ACLs) are computed client-side from the VPC/Subnet
 * lists — no BFF.
 */
export function VpcDashboardPage() {
  const { scoped } = useNamespace();

  const vpcs = useK8sWatch<Vpc>(openinfraPaths.vpcs(scoped));
  const subnets = useK8sWatch<Subnet>(openinfraPaths.subnets(scoped));
  const nats = useK8sWatch<NatGateway>(openinfraPaths.natgateways(scoped));
  const eips = useK8sWatch<ElasticIp>(openinfraPaths.elasticips(scoped));
  const tgws = useK8sWatch<TransitGateway>(openinfraPaths.transitgateways(scoped));
  const sgs = useK8sWatch<SecurityGroup>(openinfraPaths.securitygroups(scoped));
  const flowlogs = useK8sWatch<FlowLog>(openinfraPaths.flowlogs(scoped));

  const readyVpcs = vpcs.items.filter((v) => isReady(v.status?.conditions)).length;
  const readySubnets = subnets.items.filter((s) => isReady(s.status?.conditions)).length;
  const readyNats = nats.items.filter((n) => isReady(n.status?.conditions)).length;
  const readyEips = eips.items.filter((e) => isReady(e.status?.conditions)).length;

  // Derived (no separate kind): one route table per VPC; a Network ACL is any
  // subnet carrying acls; a peering is a symmetric pair declared across two VPCs.
  const aclSubnets = subnets.items.filter((s) => (s.spec?.acls?.length ?? 0) > 0).length;
  const peeringPairs = new Set<string>();
  for (const v of vpcs.items) {
    const a = v.metadata.name ?? "";
    for (const p of v.spec?.peerings ?? []) {
      peeringPairs.add([a, p.remoteVpc].sort().join("|"));
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Network />}
        title="Networking"
        description="Your VPCs, subnets, gateways and connectivity — the AWS VPC model on kube-ovn."
        actions={
          <>
            <Button asChild variant="outline">
              <Link to={RESOURCE_MAP_PATH}>
                <MapIcon className="size-4" /> Resource map
              </Link>
            </Button>
            <Button asChild>
              <Link to="/networking/create">
                <Plus className="size-4" /> Create VPC
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="VPCs"
          value={vpcs.items.length}
          sub={`${readyVpcs} ready`}
          icon={Network}
          to="/vpcs"
          loading={vpcs.isLoading}
          error={vpcs.isError}
          accent="primary"
        />
        <StatCard
          label="Subnets"
          value={subnets.items.length}
          sub={`${readySubnets} ready`}
          icon={LayoutGrid}
          to="/subnets"
          loading={subnets.isLoading}
          error={subnets.isError}
          accent="accent"
        />
        <StatCard
          label="Route Tables"
          value={vpcs.items.length}
          sub="1 per VPC"
          icon={Route}
          to="/route-tables"
          loading={vpcs.isLoading}
          error={vpcs.isError}
          accent="primary"
        />
        <StatCard
          label="NAT Gateways"
          value={nats.items.length}
          sub={`${readyNats} ready`}
          icon={Waypoints}
          to="/nat-gateways"
          loading={nats.isLoading}
          error={nats.isError}
          accent="warning"
        />
        <StatCard
          label="Elastic IPs"
          value={eips.items.length}
          sub={`${readyEips} ready`}
          icon={Milestone}
          to="/elastic-ips"
          loading={eips.isLoading}
          error={eips.isError}
          accent="accent"
        />
        <StatCard
          label="Peering Connections"
          value={peeringPairs.size}
          icon={GitBranch}
          to="/peering"
          loading={vpcs.isLoading}
          error={vpcs.isError}
          accent="primary"
        />
        <StatCard
          label="Transit Gateways"
          value={tgws.items.length}
          icon={Share2}
          to="/transit-gateways"
          loading={tgws.isLoading}
          error={tgws.isError}
          accent="success"
        />
        <StatCard
          label="Network ACLs"
          value={aclSubnets}
          sub="subnets with rules"
          icon={ListChecks}
          to="/network-acls"
          loading={subnets.isLoading}
          error={subnets.isError}
          accent="accent"
        />
        <StatCard
          label="Security Groups"
          value={sgs.items.length}
          icon={Shield}
          to="/security-groups"
          loading={sgs.isLoading}
          error={sgs.isError}
          accent="success"
        />
        <StatCard
          label="Flow Logs"
          value={flowlogs.items.length}
          sub={flowlogs.items.length ? "sampled → Loki" : "off"}
          icon={ScrollText}
          to="/flow-logs"
          loading={flowlogs.isLoading}
          error={flowlogs.isError}
          accent="warning"
        />
      </div>

      {/* "How it works" panel — honest notes where this substrate diverges from AWS. */}
      <Card>
        <CardContent className="space-y-2 p-5 text-sm text-muted-foreground">
          <h2 className="text-sm font-semibold text-foreground">
            How networking works here
          </h2>
          <ul className="list-inside list-disc space-y-1">
            <li>
              A VPC has no stored CIDR — its address space is the union of its
              subnets&rsquo; CIDRs.
            </li>
            <li>
              One route table per VPC, shared by all its subnets (no per-subnet
              associations).
            </li>
            <li>
              The NAT gateway is also the internet gateway — one border device does
              SNAT egress and routable ingress; there is no separate IGW.
            </li>
            <li>
              Network ACLs live on the subnet; VPC peering is a symmetric
              declaration on both VPCs (no accept step).
            </li>
            <li>
              Flow logs sample all node traffic to Loki — scope to a VPC or subnet
              by CIDR at view time.
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
