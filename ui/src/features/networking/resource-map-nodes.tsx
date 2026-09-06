import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Globe, Lock, Milestone, Network, Server, Waypoints, type LucideIcon } from "lucide-react";

/**
 * Custom node renderers + shared visual grammar for the networking Resource Map
 * (`resource-map-page.tsx`). Mirrors the AWS VPC console "Resource map":
 * type-columns left→right, **public subnets green / private subnets blue**, and
 * two edge meanings — **solid = relationship, dotted = network traffic**
 * (see `MAP_EDGE_STYLE`). All colours are inline hex because React Flow paints
 * SVG/inline styles, not Tailwind classes.
 */

export type MapRole =
  | "vpc"
  | "subnet-public"
  | "subnet-private"
  | "gateway"
  | "elastic-ip"
  | "target";

export const MAP_ROLE_META: Record<
  MapRole,
  { label: string; icon: LucideIcon; accent: string }
> = {
  vpc: { label: "VPC", icon: Network, accent: "#6366f1" },
  // AWS resource-map colour code: public subnets green, private subnets blue.
  "subnet-public": { label: "Public subnet", icon: Globe, accent: "#10b981" },
  "subnet-private": { label: "Private subnet", icon: Lock, accent: "#3b82f6" },
  gateway: { label: "NAT / Internet gateway", icon: Waypoints, accent: "#f59e0b" },
  "elastic-ip": { label: "Elastic IP", icon: Milestone, accent: "#8b5cf6" },
  target: { label: "Associated target", icon: Server, accent: "#64748b" },
};

/** Two AWS edge meanings mapped onto a line pattern + colourblind-safe colour. */
export type MapEdgeKind = "relationship" | "traffic";
export const MAP_EDGE_STYLE: Record<
  MapEdgeKind,
  { color: string; dash?: string; width: number }
> = {
  // solid, slate — "belongs to" / association
  relationship: { color: "#64748b", width: 1.5 },
  // dotted, Okabe-Ito orange — packets flowing to a network connection
  traffic: { color: "#E69F00", dash: "2 4", width: 2 },
};

export interface MapNodeData extends Record<string, unknown> {
  role: MapRole;
  name: string;
  /** Second line — a CIDR, an IP, or a role label. */
  subtitle?: string;
  /** Fully-resolved detail path; when set, the node is click-to-navigate. */
  href?: string;
  /** Dim to background when another node is hovered (neighbour-highlight). */
  dimmed?: boolean;
}

/** One node renderer for every map role — a Card-like box with an accent rail. */
export function MapNode({ data, selected }: NodeProps) {
  const d = data as MapNodeData;
  const meta = MAP_ROLE_META[d.role] ?? MAP_ROLE_META.vpc;
  const Icon = meta.icon;
  return (
    <div
      className={`rounded-md border bg-card py-2 pl-2 pr-3 shadow-sm transition-opacity ${
        selected ? "ring-2 ring-primary" : ""
      } ${d.href ? "cursor-pointer" : "cursor-default"}`}
      style={{
        minWidth: 176,
        borderLeft: `4px solid ${meta.accent}`,
        opacity: d.dimmed ? 0.25 : 1,
      }}
      title={d.href ? `Open ${d.name}` : d.name}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div className="flex items-center gap-2">
        <Icon className="size-4 shrink-0" style={{ color: meta.accent }} />
        <span className="truncate font-medium" style={{ maxWidth: 200 }}>
          {d.name || "unnamed"}
        </span>
      </div>
      <div
        className="mt-0.5 truncate text-[11px] text-muted-foreground"
        style={{ maxWidth: 200 }}
      >
        {d.subtitle ?? meta.label}
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

export const mapNodeTypes = { map: MapNode };
