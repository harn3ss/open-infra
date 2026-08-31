import {
  Camera,
  Bomb,
  BrainCircuit,
  BrainCog,
  Boxes,
  Building2,
  Database,
  Disc3,
  FlaskConical,
  DollarSign,
  FolderTree,
  Gauge,
  Globe,
  HardDrive,
  Layers,
  LayoutDashboard,
  LineChart,
  Monitor,
  Network,
  Package,
  Radio,
  Route,
  Search,
  ScrollText,
  Send,
  Target,
  BadgeCheck,
  ClipboardCheck,
  Clock,
  KeyRound,
  Server,
  Tags,
  Workflow,
  FileText,
  Shield,
  ShieldCheck,
  Users,
  UsersRound,
  Waypoints,
  Zap,
  type LucideIcon,
} from "lucide-react";
import type { AppConfig } from "@/lib/api";

export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  /** Optional sidebar group header shown above the first item of the group. */
  section?: string;
  /** Match child routes too (e.g. /applications/$name). */
  matchPrefix?: boolean;
  /**
   * Name of a boolean AppConfig flag that must be true for this item to appear.
   * Used to keep non-essential/privileged surfaces (e.g. Chaos) hidden unless the
   * deployment explicitly enables them — least functionality (NIST CM-7).
   */
  flag?: "chaosUiEnabled";
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
  { label: "GraphQL", to: "/graphql", icon: Waypoints, matchPrefix: true, section: "Compute" },
  { label: "Virtual Machines", to: "/vms", icon: Monitor, matchPrefix: true, section: "Compute" },
  { label: "Models", to: "/models", icon: BrainCircuit, matchPrefix: true, section: "Compute" },
  { label: "Training Jobs", to: "/trainingjobs", icon: BrainCog, matchPrefix: true, section: "Compute" },
  { label: "Model Registry", to: "/model-registry", icon: Package, matchPrefix: true, section: "Compute" },
  { label: "Model Monitor", to: "/model-monitor", icon: Gauge, matchPrefix: true, section: "Compute" },
  { label: "Batch Transform", to: "/batch-transform", icon: Layers, matchPrefix: true, section: "Compute" },
  { label: "Tuning Jobs", to: "/tuning", icon: Target, matchPrefix: true, section: "Compute" },
  { label: "Processing Jobs", to: "/processing", icon: FlaskConical, matchPrefix: true, section: "Compute" },
  { label: "State Machines", to: "/statemachines", icon: Route, matchPrefix: true, section: "Compute" },

  { label: "Databases", to: "/databases", icon: Database, matchPrefix: true, section: "Data" },
  { label: "Query", to: "/queries", icon: Search, matchPrefix: true, section: "Data" },
  { label: "Data Flows", to: "/dataflows", icon: Workflow, matchPrefix: true, section: "Data" },
  { label: "Lineage", to: "/lineage", icon: Waypoints, matchPrefix: true, section: "Data" },
  { label: "Streams", to: "/streams", icon: Radio, matchPrefix: true, section: "Data" },
  { label: "Queues", to: "/queues", icon: Send, matchPrefix: true, section: "Data" },
  { label: "Buckets", to: "/buckets", icon: HardDrive, matchPrefix: true, section: "Data" },

  { label: "Volumes", to: "/volumes", icon: Disc3, matchPrefix: true, section: "Storage" },
  { label: "File Shares", to: "/fileshares", icon: FolderTree, matchPrefix: true, section: "Storage" },
  { label: "Snapshots", to: "/snapshots", icon: Camera, matchPrefix: true, section: "Storage" },

  { label: "Users", to: "/users", icon: Users, matchPrefix: true, section: "Security & Identity" },
  { label: "Groups", to: "/groups", icon: UsersRound, matchPrefix: true, section: "Security & Identity" },
  { label: "Policies", to: "/policies", icon: FileText, matchPrefix: true, section: "Security & Identity" },
  { label: "Roles", to: "/roles", icon: ShieldCheck, matchPrefix: true, section: "Security & Identity" },
  { label: "Grants", to: "/grants", icon: Clock, matchPrefix: true, section: "Security & Identity" },
  { label: "Security Groups", to: "/security-groups", icon: Shield, matchPrefix: true, section: "Security & Identity" },
  { label: "Active Directory", to: "/directories", icon: Building2, matchPrefix: true, section: "Security & Identity" },
  { label: "Data Classification", to: "/data-classification", icon: Tags, matchPrefix: true, section: "Security & Identity" },
  { label: "Encryption Keys", to: "/encryption", icon: KeyRound, matchPrefix: true, section: "Security & Identity" },
  { label: "Audit", to: "/audit", icon: ScrollText, matchPrefix: true, section: "Security & Identity" },
  { label: "Attestation", to: "/attestation", icon: BadgeCheck, matchPrefix: true, section: "Security & Identity" },
  { label: "Access Review", to: "/access-review", icon: ClipboardCheck, matchPrefix: true, section: "Security & Identity" },

  { label: "Workloads", to: "/workloads", icon: Network, matchPrefix: true, section: "Cluster" },
  { label: "Nodes", to: "/nodes", icon: Server, matchPrefix: true, section: "Cluster" },
  { label: "Network", to: "/network", icon: Globe, matchPrefix: true, section: "Cluster" },

  { label: "Monitoring", to: "/monitoring", icon: LineChart, section: "Observability" },
  { label: "Chaos", to: "/chaos", icon: Bomb, matchPrefix: true, section: "Observability", flag: "chaosUiEnabled" },
  { label: "Cost Explorer", to: "/cost", icon: DollarSign, section: "Observability" },
];

/** Section names in display order (derived from NAV_ITEMS, unique, non-empty). */
export const NAV_SECTIONS: string[] = NAV_ITEMS.reduce<string[]>((acc, item) => {
  if (item.section && !acc.includes(item.section)) acc.push(item.section);
  return acc;
}, []);

/**
 * Whether a nav item is visible given the runtime config. Items carrying a `flag`
 * (e.g. Chaos → chaosUiEnabled) appear only when that config flag is true — so
 * privileged/non-essential surfaces stay hidden unless explicitly enabled.
 */
export function navItemVisible(item: NavItem, config: AppConfig): boolean {
  return !item.flag || Boolean(config[item.flag]);
}
