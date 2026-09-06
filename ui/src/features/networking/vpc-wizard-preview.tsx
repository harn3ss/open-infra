import { useMemo } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Globe,
  Lock,
  Network,
  Route as RouteIcon,
  Waypoints,
  Server,
  type LucideIcon,
} from "lucide-react";

/**
 * A single planned subnet, as the wizard form describes it (nothing created yet).
 */
export interface PreviewSubnet {
  name: string;
  cidr: string;
  isPublic: boolean;
}

/**
 * The whole planned topology the wizard will provision, driven live by the form.
 * The preview is read-only and inert — it reflects the *plan*, it does not create.
 */
export interface VpcPreviewModel {
  vpcName: string;
  /** UI-only planning supernet (not persisted on the Vpc). */
  planningCidr: string;
  subnets: PreviewSubnet[];
  /** The border gateway (NAT + internet-gateway role), if the plan includes one. */
  nat?: { name: string; internalIp: string } | null;
  /** The Elastic IP hosted on the gateway, if the plan includes one. */
  eip?: { name: string; address: string } | null;
  /** Whether a 0.0.0.0/0 default route is added to the Vpc (true iff a NAT is planned). */
  hasDefaultRoute: boolean;
}

// ── colours (public=green, private=blue — AWS resource-map grammar) ──────────
const ACCENT = {
  vpc: "#6366f1",
  public: "#10b981",
  private: "#3b82f6",
  route: "#64748b",
  gateway: "#f59e0b",
  eip: "#0ea5e9",
} as const;

interface PreviewNodeData extends Record<string, unknown> {
  title: string;
  subtitle: string;
  accent: string;
  icon: LucideIcon;
  badge?: string;
}

function PreviewNode({ data }: NodeProps) {
  const d = data as PreviewNodeData;
  const Icon = d.icon;
  return (
    <div
      className="rounded-md border bg-card py-1.5 pl-2 pr-2.5 shadow-sm"
      style={{ minWidth: 150, borderLeft: `4px solid ${d.accent}` }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div className="flex items-center gap-1.5">
        <Icon className="size-3.5" style={{ color: d.accent }} aria-hidden />
        <span className="truncate text-xs font-medium" style={{ maxWidth: 150 }}>
          {d.title}
        </span>
        {d.badge ? (
          <span
            className="ml-auto rounded px-1 text-[9px] font-medium uppercase tracking-wide"
            style={{ color: d.accent, background: `${d.accent}1a` }}
          >
            {d.badge}
          </span>
        ) : null}
      </div>
      <div
        className="mt-0.5 truncate text-[10px] text-muted-foreground"
        style={{ maxWidth: 190 }}
      >
        {d.subtitle}
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { preview: PreviewNode };

// lane x-positions (type columns, left→right by traffic flow — minus AZ lanes)
const LANE = { vpc: 0, subnet: 210, route: 420, gateway: 640, eip: 860 } as const;
const ROW_H = 72;

function styledEdge(
  id: string,
  source: string,
  target: string,
  kind: "assoc" | "member" | "route" | "egress" | "eip",
): Edge {
  // Three redundant cues (pattern + word + colour) — never colour alone.
  const map = {
    member: { color: ACCENT.vpc, dash: "none", width: 1.5, label: "" },
    assoc: { color: ACCENT.route, dash: "none", width: 1.5, label: "" },
    route: { color: ACCENT.gateway, dash: "2 4", width: 2, label: "0.0.0.0/0" },
    egress: { color: ACCENT.private, dash: "6 4", width: 1.5, label: "egress" },
    eip: { color: ACCENT.eip, dash: "none", width: 1.5, label: "EIP" },
  }[kind];
  return {
    id,
    source,
    target,
    label: map.label || undefined,
    style: { stroke: map.color, strokeWidth: map.width, strokeDasharray: map.dash },
    labelStyle: { fontSize: 9, fill: map.color },
    labelBgStyle: { fill: "var(--card, #fff)", fillOpacity: 0.85 },
  };
}

function buildGraph(model: VpcPreviewModel): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const rows = Math.max(model.subnets.length, 1);
  const midY = ((rows - 1) * ROW_H) / 2;

  nodes.push({
    id: "vpc",
    type: "preview",
    position: { x: LANE.vpc, y: midY },
    data: {
      title: model.vpcName || "vpc",
      subtitle: model.planningCidr || "planning CIDR",
      accent: ACCENT.vpc,
      icon: Network,
      badge: "VPC",
    } satisfies PreviewNodeData,
    draggable: false,
  });

  nodes.push({
    id: "route",
    type: "preview",
    position: { x: LANE.route, y: midY },
    data: {
      title: `${model.vpcName || "vpc"} routes`,
      subtitle: model.hasDefaultRoute ? "local + 0.0.0.0/0" : "local only",
      accent: ACCENT.route,
      icon: RouteIcon,
      badge: "RT",
    } satisfies PreviewNodeData,
    draggable: false,
  });
  edges.push(styledEdge("vpc-route", "vpc", "route", "member"));

  model.subnets.forEach((s, i) => {
    const id = `subnet-${i}`;
    nodes.push({
      id,
      type: "preview",
      position: { x: LANE.subnet, y: i * ROW_H },
      data: {
        title: s.name || `subnet-${i + 1}`,
        subtitle: s.cidr || "—",
        accent: s.isPublic ? ACCENT.public : ACCENT.private,
        icon: s.isPublic ? Globe : Lock,
        badge: s.isPublic ? "public" : "private",
      } satisfies PreviewNodeData,
      draggable: false,
    });
    // every subnet associates to the single VPC route table
    edges.push(styledEdge(`${id}-route`, id, "route", "assoc"));
  });

  if (model.nat) {
    nodes.push({
      id: "nat",
      type: "preview",
      position: { x: LANE.gateway, y: midY },
      data: {
        title: model.nat.name || "nat",
        subtitle: model.nat.internalIp || "internet + NAT",
        accent: ACCENT.gateway,
        icon: Waypoints,
        badge: "GW",
      } satisfies PreviewNodeData,
      draggable: false,
    });
    // default route → gateway (traffic), and each private subnet egresses via it
    edges.push(styledEdge("route-nat", "route", "nat", "route"));
    model.subnets.forEach((s, i) => {
      if (!s.isPublic) edges.push(styledEdge(`subnet-${i}-nat`, `subnet-${i}`, "nat", "egress"));
    });

    if (model.eip) {
      nodes.push({
        id: "eip",
        type: "preview",
        position: { x: LANE.eip, y: midY },
        data: {
          title: model.eip.name || "eip",
          subtitle: model.eip.address || "auto-allocated",
          accent: ACCENT.eip,
          icon: Server,
          badge: "EIP",
        } satisfies PreviewNodeData,
        draggable: false,
      });
      edges.push(styledEdge("nat-eip", "nat", "eip", "eip"));
    }
  }

  return { nodes, edges };
}

function PreviewCanvas({ model }: { model: VpcPreviewModel }) {
  const { nodes, edges } = useMemo(() => buildGraph(model), [model]);
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.15 }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      panOnDrag
      zoomOnScroll={false}
      proOptions={{ hideAttribution: true }}
    >
      <Background gap={16} />
      <Controls showInteractive={false} position="bottom-right" />
    </ReactFlow>
  );
}

/**
 * The wizard's live "resource map" preview — the crown-jewel side pane. It redraws
 * on every form change (no refresh) and mirrors AWS's "VPC and more" preview,
 * arranged in type-columns (VPC → subnets → route table → gateway → EIP) minus the
 * AZ lanes this substrate has no analog for. Read-only: it reflects the plan, it is
 * not an editor.
 */
export function VpcWizardPreview({ model }: { model: VpcPreviewModel }) {
  const counts = [
    "1 VPC",
    model.subnets.length ? `${model.subnets.length} subnet${model.subnets.length === 1 ? "" : "s"}` : null,
    model.hasDefaultRoute ? "default route" : null,
    model.nat ? "1 NAT gateway" : null,
    model.eip ? "1 Elastic IP" : null,
  ].filter(Boolean) as string[];

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Preview
        </span>
        <span className="text-[10px] text-muted-foreground">updates live</span>
      </div>
      <div className="h-[300px] w-full">
        <ReactFlowProvider>
          <PreviewCanvas model={model} />
        </ReactFlowProvider>
      </div>
      <div className="space-y-1.5 border-t border-border px-3 py-2">
        <p className="text-[11px] text-muted-foreground">
          Creates: {counts.join(" · ")}
        </p>
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
          <Legend color={ACCENT.public} label="public subnet" />
          <Legend color={ACCENT.private} label="private subnet" />
          <Legend color={ACCENT.gateway} label="gateway / route" />
        </div>
      </div>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className="inline-block size-2 rounded-sm" style={{ background: color }} aria-hidden />
      {label}
    </span>
  );
}
