import {
  ArrowRightLeft,
  BrainCircuit,
  Boxes,
  Building2,
  Database,
  Disc3,
  FolderTree,
  Globe,
  HardDrive,
  LayoutDashboard,
  LineChart,
  Monitor,
  Network,
  Send,
  Server,
  Zap,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  /** Optional sidebar group header shown above the first item of the group. */
  section?: string;
  /** Match child routes too (e.g. /applications/$name). */
  matchPrefix?: boolean;
}

/** Primary sidebar navigation, grouped like a cloud console. */
export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/", icon: LayoutDashboard },

  { label: "Applications", to: "/applications", icon: Boxes, matchPrefix: true, section: "Compute" },
  { label: "Functions", to: "/functions", icon: Zap, matchPrefix: true, section: "Compute" },
  { label: "Virtual Machines", to: "/vms", icon: Monitor, matchPrefix: true, section: "Compute" },

  { label: "Volumes", to: "/volumes", icon: Disc3, matchPrefix: true, section: "Storage" },
  { label: "File Shares", to: "/fileshares", icon: FolderTree, matchPrefix: true, section: "Storage" },

  { label: "Active Directory", to: "/directories", icon: Building2, matchPrefix: true, section: "Identity" },

  { label: "Models", to: "/models", icon: BrainCircuit, matchPrefix: true, section: "AI" },

  { label: "Databases", to: "/databases", icon: Database, matchPrefix: true, section: "Data" },
  { label: "Migrations", to: "/migrations", icon: ArrowRightLeft, matchPrefix: true, section: "Data" },
  { label: "Buckets", to: "/buckets", icon: HardDrive, matchPrefix: true, section: "Data" },
  { label: "Queues", to: "/queues", icon: Send, matchPrefix: true, section: "Data" },

  { label: "Workloads", to: "/workloads", icon: Network, matchPrefix: true, section: "Cluster" },
  { label: "Nodes", to: "/nodes", icon: Server, matchPrefix: true, section: "Cluster" },
  { label: "Network", to: "/network", icon: Globe, matchPrefix: true, section: "Cluster" },

  { label: "Monitoring", to: "/monitoring", icon: LineChart, section: "Observability" },
];
