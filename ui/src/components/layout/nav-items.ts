import {
  Boxes,
  LayoutDashboard,
  LineChart,
  Network,
  Server,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  /** Match child routes too (e.g. /applications/$name). */
  matchPrefix?: boolean;
}

/** Primary sidebar navigation. */
export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/", icon: LayoutDashboard },
  { label: "Applications", to: "/applications", icon: Boxes, matchPrefix: true },
  { label: "Workloads", to: "/workloads", icon: Network, matchPrefix: true },
  { label: "Nodes", to: "/nodes", icon: Server, matchPrefix: true },
  { label: "Monitoring", to: "/monitoring", icon: LineChart },
];
