import {
  Camera,
  Bomb,
  BrainCircuit,
  Boxes,
  Building2,
  Database,
  Disc3,
  DollarSign,
  FolderTree,
  Globe,
  HardDrive,
  LayoutDashboard,
  LineChart,
  Monitor,
  Network,
  Radio,
  Search,
  Send,
  Server,
  Workflow,
  Shield,
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

/**
 * Primary sidebar navigation, grouped like a cloud console. Consolidated to six
 * sections (no single-item groups) ordered general→specific by frequency of use,
 * per Cloudscape's side-nav guidance. Dashboard stays ungrouped at the top.
 */
export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/", icon: LayoutDashboard },

  { label: "Applications", to: "/applications", icon: Boxes, matchPrefix: true, section: "Compute" },
  { label: "Functions", to: "/functions", icon: Zap, matchPrefix: true, section: "Compute" },
  { label: "Virtual Machines", to: "/vms", icon: Monitor, matchPrefix: true, section: "Compute" },
  { label: "Models", to: "/models", icon: BrainCircuit, matchPrefix: true, section: "Compute" },

  { label: "Databases", to: "/databases", icon: Database, matchPrefix: true, section: "Data" },
  { label: "Query", to: "/queries", icon: Search, matchPrefix: true, section: "Data" },
  { label: "Data Flows", to: "/dataflows", icon: Workflow, matchPrefix: true, section: "Data" },
  { label: "Streams", to: "/streams", icon: Radio, matchPrefix: true, section: "Data" },
  { label: "Queues", to: "/queues", icon: Send, matchPrefix: true, section: "Data" },
  { label: "Buckets", to: "/buckets", icon: HardDrive, matchPrefix: true, section: "Data" },

  { label: "Volumes", to: "/volumes", icon: Disc3, matchPrefix: true, section: "Storage" },
  { label: "File Shares", to: "/fileshares", icon: FolderTree, matchPrefix: true, section: "Storage" },
  { label: "Snapshots", to: "/snapshots", icon: Camera, matchPrefix: true, section: "Storage" },

  { label: "Security Groups", to: "/security-groups", icon: Shield, matchPrefix: true, section: "Security & Identity" },
  { label: "Active Directory", to: "/directories", icon: Building2, matchPrefix: true, section: "Security & Identity" },

  { label: "Workloads", to: "/workloads", icon: Network, matchPrefix: true, section: "Cluster" },
  { label: "Nodes", to: "/nodes", icon: Server, matchPrefix: true, section: "Cluster" },
  { label: "Network", to: "/network", icon: Globe, matchPrefix: true, section: "Cluster" },

  { label: "Monitoring", to: "/monitoring", icon: LineChart, section: "Observability" },
  { label: "Chaos", to: "/chaos", icon: Bomb, matchPrefix: true, section: "Observability" },
  { label: "Cost Explorer", to: "/cost", icon: DollarSign, section: "Observability" },
];

/** Section names in display order (derived from NAV_ITEMS, unique, non-empty). */
export const NAV_SECTIONS: string[] = NAV_ITEMS.reduce<string[]>((acc, item) => {
  if (item.section && !acc.includes(item.section)) acc.push(item.section);
  return acc;
}, []);
