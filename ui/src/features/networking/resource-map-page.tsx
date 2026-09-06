import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Waypoints } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { ElasticIp, NatGateway, Subnet, Vpc } from "@/types/k8s";
import {
  MAP_EDGE_STYLE,
  MAP_ROLE_META,
  mapNodeTypes,
  type MapEdgeKind,
  type MapNodeData,
} from "@/features/networking/resource-map-nodes";

// Auto-layout geometry — resources sit in type-columns left→right following the
// AWS resource map (VPC → Subnets → NAT gateways → Elastic IPs), grouped by VPC.
const COL_X = { vpc: 40, subnet: 340, gateway: 660, eip: 980, target: 1280 };
const ROW_H = 92;
const GROUP_GAP = 40;

const nsOf = (o: { metadata: { namespace?: string } }) => o.metadata.namespace ?? "default";

function edgeOf(
  source: string,
  target: string,
  kind: MapEdgeKind,
  label: string,
): Edge {
  const st = MAP_EDGE_STYLE[kind];
  return {
    id: `e:${source}->${target}`,
    source,
    target,
    label,
    type: "smoothstep",
    animated: false,
    data: { kind },
    style: { stroke: st.color, strokeWidth: st.width, strokeDasharray: st.dash ?? "none" },
    labelBgStyle: { fill: "var(--card)", fillOpacity: 0.85 },
    labelStyle: { fontSize: 10, fill: st.color },
  };
}

/** Aggregate the k8s lists (client-side, no BFF) into a positioned topology. */
function buildGraph(
  vpcs: Vpc[],
  subnets: Subnet[],
  nats: NatGateway[],
  eips: ElasticIp[],
): { nodes: Node<MapNodeData>[]; edges: Edge[] } {
  const nodes: Node<MapNodeData>[] = [];
  const edges: Edge[] = [];

  // Bucket subnets + NAT gateways under the VPC they reference (undefined = the
  // kube-ovn default VPC, "ovn-cluster").
  const groups = new Map<string, { subnets: Subnet[]; nats: NatGateway[] }>();
  const bucket = (k: string) => {
    let e = groups.get(k);
    if (!e) {
      e = { subnets: [], nats: [] };
      groups.set(k, e);
    }
    return e;
  };
  subnets.forEach((s) => bucket(s.spec?.vpc || "ovn-cluster").subnets.push(s));
  nats.forEach((n) => bucket(n.spec?.vpc || "ovn-cluster").nats.push(n));
  const vpcNames = new Set(vpcs.map((v) => v.metadata.name).filter(Boolean) as string[]);
  vpcs.forEach((v) => v.metadata.name && bucket(v.metadata.name)); // keep empty VPCs visible

  // Real VPCs first (in list order), then any referenced-but-undeclared group
  // (e.g. the implicit default VPC) as a non-clickable node.
  const ordered: { key: string; vpc?: Vpc }[] = [
    ...vpcs
      .filter((v) => v.metadata.name)
      .map((v) => ({ key: v.metadata.name as string, vpc: v })),
    ...[...groups.keys()]
      .filter((k) => !vpcNames.has(k))
      .map((k) => ({ key: k, vpc: undefined })),
  ];

  let cursorY = 0;
  for (const { key, vpc } of ordered) {
    const g = groups.get(key)!;
    const gEips = new Map<string, ElasticIp[]>(); // nat name -> its EIPs
    g.nats.forEach((n) =>
      gEips.set(
        n.metadata.name ?? "",
        eips.filter((e) => e.spec?.natGateway === n.metadata.name),
      ),
    );
    const eipList = [...gEips.values()].flat();
    const targetCount = eipList.filter((e) => e.spec?.target).length;
    const rows = Math.max(1, g.subnets.length, g.nats.length, eipList.length, targetCount);
    const bandH = rows * ROW_H;

    // VPC node (centred in the band).
    const vpcId = `vpc:${key}`;
    nodes.push({
      id: vpcId,
      type: "map",
      draggable: false,
      position: { x: COL_X.vpc, y: cursorY + bandH / 2 - 28 },
      data: {
        role: "vpc",
        name: vpc ? key : `${key} (default)`,
        subtitle: `${g.subnets.length} subnet${g.subnets.length === 1 ? "" : "s"}`,
        href: vpc ? `/vpcs/${nsOf(vpc)}/${key}` : undefined,
      },
    });

    // Subnets column.
    const subnetIdByName = new Map<string, string>();
    g.subnets.forEach((s, i) => {
      const id = `subnet:${nsOf(s)}/${s.metadata.name}`;
      subnetIdByName.set(s.metadata.name ?? "", id);
      const isPublic = s.spec?.private === false;
      nodes.push({
        id,
        type: "map",
        draggable: false,
        position: { x: COL_X.subnet, y: cursorY + i * ROW_H },
        data: {
          role: isPublic ? "subnet-public" : "subnet-private",
          name: s.metadata.name ?? "",
          subtitle: `${s.spec?.cidr ?? "—"} · ${isPublic ? "public" : "private"}`,
          href: `/subnets/${nsOf(s)}/${s.metadata.name}`,
        },
      });
      edges.push(edgeOf(vpcId, id, "relationship", "contains"));
    });

    // NAT gateways column + Elastic IPs + associated targets.
    let eipRow = 0;
    let targetRow = 0;
    g.nats.forEach((n, i) => {
      const natId = `nat:${nsOf(n)}/${n.metadata.name}`;
      nodes.push({
        id: natId,
        type: "map",
        draggable: false,
        position: { x: COL_X.gateway, y: cursorY + i * ROW_H },
        data: {
          role: "gateway",
          name: n.metadata.name ?? "",
          subtitle: `internal ${n.spec?.internalIp ?? "—"}`,
          href: `/nat-gateways/${nsOf(n)}/${n.metadata.name}`,
        },
      });
      // The gateway's internal leg lives on a public subnet — dotted = traffic.
      const hostSubnet = n.spec?.subnet ? subnetIdByName.get(n.spec.subnet) : undefined;
      if (hostSubnet) edges.push(edgeOf(hostSubnet, natId, "traffic", "gateway"));
      else edges.push(edgeOf(vpcId, natId, "relationship", "gateway"));

      for (const e of gEips.get(n.metadata.name ?? "") ?? []) {
        const eipId = `eip:${nsOf(e)}/${e.metadata.name}`;
        const addr = e.status?.address || e.spec?.address || "auto";
        nodes.push({
          id: eipId,
          type: "map",
          draggable: false,
          position: { x: COL_X.eip, y: cursorY + eipRow * ROW_H },
          data: {
            role: "elastic-ip",
            name: e.metadata.name ?? "",
            subtitle: `${addr} · ${e.spec?.mode ?? "fip"}`,
            href: `/elastic-ips/${nsOf(e)}/${e.metadata.name}`,
          },
        });
        eipRow += 1;
        edges.push(edgeOf(natId, eipId, "relationship", "allocates"));

        if (e.spec?.target) {
          const tId = `target:${eipId}`;
          nodes.push({
            id: tId,
            type: "map",
            draggable: false,
            position: { x: COL_X.target, y: cursorY + targetRow * ROW_H },
            data: {
              role: "target",
              name: e.spec.target,
              subtitle: `${e.spec.mode === "dnat" ? "DNAT" : "FIP"} target`,
            },
          });
          targetRow += 1;
          edges.push(edgeOf(eipId, tId, "traffic", "ingress"));
        }
      }
    });

    cursorY += bandH + GROUP_GAP;
  }

  return { nodes, edges };
}

function MapInner() {
  const { scoped } = useNamespace();
  const navigate = useNavigate();

  const vpcs = useK8sWatch<Vpc>(openinfraPaths.vpcs(scoped));
  const subnets = useK8sWatch<Subnet>(openinfraPaths.subnets(scoped));
  const nats = useK8sWatch<NatGateway>(openinfraPaths.natgateways(scoped));
  const eips = useK8sWatch<ElasticIp>(openinfraPaths.elasticips(scoped));

  const { nodes: baseNodes, edges: baseEdges } = useMemo(
    () => buildGraph(vpcs.items, subnets.items, nats.items, eips.items),
    [vpcs.items, subnets.items, nats.items, eips.items],
  );

  // Hover a node → highlight it + its neighbours, dim the rest.
  const [hovered, setHovered] = useState<string | null>(null);
  const neighborIds = useMemo(() => {
    if (!hovered) return null;
    const s = new Set<string>([hovered]);
    for (const e of baseEdges) {
      if (e.source === hovered) s.add(e.target);
      if (e.target === hovered) s.add(e.source);
    }
    return s;
  }, [hovered, baseEdges]);

  const nodes = useMemo<Node<MapNodeData>[]>(
    () =>
      baseNodes.map((n) => ({
        ...n,
        data: { ...n.data, dimmed: neighborIds ? !neighborIds.has(n.id) : false },
      })),
    [baseNodes, neighborIds],
  );
  const edges = useMemo<Edge[]>(
    () =>
      baseEdges.map((e) => {
        const active = !hovered || e.source === hovered || e.target === hovered;
        return {
          ...e,
          style: { ...e.style, opacity: active ? 1 : 0.1 },
          labelStyle: { ...(e.labelStyle as object), opacity: active ? 1 : 0.1 },
        };
      }),
    [baseEdges, hovered],
  );

  const onNodeClick = useCallback(
    (_: unknown, n: Node) => {
      const href = (n.data as MapNodeData).href;
      if (href) navigate({ to: href });
    },
    [navigate],
  );

  const loading = (vpcs.isLoading || subnets.isLoading) && baseNodes.length === 0;
  const coreError = vpcs.isError && subnets.isError;

  if (loading) return <LoadingState label="Loading network topology…" />;
  if (coreError && baseNodes.length === 0)
    return <ErrorState error={vpcs.error ?? subnets.error} onRetry={vpcs.refetch} />;
  if (baseNodes.length === 0)
    return (
      <EmptyState
        icon={<Waypoints className="size-6" />}
        title="No network resources to map"
        description="Create a VPC and subnets — they'll appear here as an interactive topology, alongside any NAT gateways and Elastic IPs."
      />
    );

  return (
    <div className="relative h-[calc(100vh-13rem)] rounded-md border">
      {/* Legend — the map's colour + line grammar (AWS resource-map conventions). */}
      <div className="absolute right-2 top-2 z-10 flex flex-col gap-1 rounded-md border bg-card/90 p-2 text-[11px] backdrop-blur">
        <span className="font-medium text-muted-foreground">Legend</span>
        <LegendDot color={MAP_ROLE_META["subnet-public"].accent} label="Public subnet" />
        <LegendDot color={MAP_ROLE_META["subnet-private"].accent} label="Private subnet" />
        <LegendDot color={MAP_ROLE_META.gateway.accent} label="NAT / internet gateway" />
        <LegendDot color={MAP_ROLE_META["elastic-ip"].accent} label="Elastic IP" />
        <div className="mt-0.5 border-t pt-1" />
        <LegendLine
          color={MAP_EDGE_STYLE.relationship.color}
          width={MAP_EDGE_STYLE.relationship.width}
          label="relationship"
        />
        <LegendLine
          color={MAP_EDGE_STYLE.traffic.color}
          dash={MAP_EDGE_STYLE.traffic.dash}
          width={MAP_EDGE_STYLE.traffic.width}
          label="network traffic"
        />
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={mapNodeTypes}
        onNodeClick={onNodeClick}
        onNodeMouseEnter={(_, n) => setHovered(n.id)}
        onNodeMouseLeave={() => setHovered(null)}
        nodesConnectable={false}
        nodesDraggable={false}
        elementsSelectable
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable />
      </ReactFlow>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="size-2.5 rounded-sm" style={{ background: color }} aria-hidden />
      <span className="text-muted-foreground">{label}</span>
    </span>
  );
}

function LegendLine({
  color,
  dash,
  width = 2,
  label,
}: {
  color: string;
  dash?: string;
  width?: number;
  label: string;
}) {
  return (
    <span className="flex items-center gap-1.5">
      <svg width="22" height="6" aria-hidden="true" className="shrink-0">
        <line
          x1="0"
          y1="3"
          x2="22"
          y2="3"
          stroke={color}
          strokeWidth={width}
          strokeDasharray={dash}
          strokeLinecap="round"
        />
      </svg>
      <span className="text-muted-foreground">{label}</span>
    </span>
  );
}

export function ResourceMapPage() {
  return (
    <DetailShell
      backTo="/networking"
      backLabel="VPC Dashboard"
      icon={<Waypoints className="size-5" />}
      title="Resource map"
      subtitle="Your VPCs, subnets, NAT gateways and Elastic IPs as one topology. Hover to trace connections; click a resource to open it."
    >
      <ReactFlowProvider>
        <MapInner />
      </ReactFlowProvider>
    </DetailShell>
  );
}
