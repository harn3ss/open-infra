import {
  AppWindow,
  ArrowRightLeft,
  Camera,
  Bomb,
  CalendarClock,
  CopyPlus,
  BrainCircuit,
  BrainCog,
  Boxes,
  Building2,
  Database,
  DatabaseZap,
  Disc3,
  FileBadge,
  GitCompareArrows,
  IdCard,
  Mail,
  SlidersHorizontal,
  Webhook,
  Fingerprint,
  FlaskConical,
  DollarSign,
  FolderTree,
  Gauge,
  Globe,
  HardDrive,
  Image,
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
  Share2,
  Target,
  BadgeCheck,
  ClipboardCheck,
  Clock,
  KeyRound,
  Server,
  Table2,
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

/**
 * A leaf navigation destination — either the list/landing of a *flat* service, or
 * one item in a *multi* service's sub-nav. Also the shape the ⌘K command palette
 * and the pin/recent store operate over (see NAV_ITEMS below).
 */
export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  /**
   * Display-only grouping hint for the command palette (the parent service name
   * for a sub-nav item, or the AWS category for a flat service).
   */
  section?: string;
  /** Match child routes too (e.g. /applications/$name). Matching is prefix-based. */
  matchPrefix?: boolean;
  /**
   * Name of a boolean AppConfig flag that must be true for this item to appear.
   * Keeps non-essential/privileged surfaces (e.g. Chaos) hidden unless the
   * deployment explicitly enables them — least functionality (NIST CM-7).
   */
  flag?: "chaosUiEnabled";
}

/**
 * A **service** is the thing you *enter* — the AWS "Level 1" (IAM, VPC, S3,
 * Lambda…). The console nav is two levels: a category → service launcher, then
 * you enter a service and (for multi-resource services) the rail swaps to that
 * service's own sub-nav.
 *
 * - A **flat** (single-resource) service has no `children`; its `to` *is* its one
 *   list, so "enter → list → detail" is the whole service (S3, Lambda, DynamoDB…).
 * - A **multi** service carries its sub-nav in `children` and a landing `to`
 *   (a dashboard, or its first child where no dashboard route exists yet).
 */
export interface Service {
  /** Service display name (kept close to open-infra's existing labels). */
  label: string;
  icon: LucideIcon;
  /** AWS-style top-level category this service is launched from. */
  category: string;
  /** Landing route (dashboard for a multi service, or its list). Always navigable. */
  to: string;
  /** Sub-nav items for a multi service. Absent/empty ⇒ a flat service. */
  children?: NavItem[];
  /**
   * Extra route prefixes that belong to this service but have no clickable
   * sub-nav leaf (e.g. Step Functions owns /executions/* which is reached from a
   * state machine, not the rail). Used for route→service resolution only.
   */
  routePrefixes?: string[];
  /** Config flag gate (as NavItem.flag) — e.g. Chaos → chaosUiEnabled. */
  flag?: "chaosUiEnabled";
}

/** AWS-style categories, in launcher display order. Last is the open-infra native. */
export const CATEGORIES: string[] = [
  "Compute",
  "Front-end Web & Mobile",
  "Machine Learning",
  "Storage",
  "Database",
  "Analytics",
  "Application Integration",
  "Customer Engagement",
  "Networking & Content Delivery",
  "Security, Identity & Compliance",
  "Management & Governance",
  "Cluster",
];

/**
 * The full service tree. Order within a category is launcher display order.
 * `[MULTI]` services carry `children`; every other service is flat.
 *
 * Route reachability is preserved: every route in router.tsx is reachable either
 * as a service landing, a sub-nav leaf, or (for param/detail/nested routes) via
 * prefix / `routePrefixes` resolution — nothing 404s.
 */
export const SERVICES: Service[] = [
  // ── Compute ────────────────────────────────────────────────────────────────
  { label: "Applications", icon: Boxes, category: "Compute", to: "/applications" }, // ECS / App Runner
  {
    // EC2 — Instances + Images (light 2-level). Volumes/EBS stay in Storage per the target doc.
    label: "Virtual Machines",
    icon: Monitor,
    category: "Compute",
    to: "/vms",
    children: [
      { label: "Instances", to: "/vms", icon: Monitor, matchPrefix: true },
      { label: "Images", to: "/vms/images", icon: Image, matchPrefix: true },
    ],
  },
  { label: "Auto Scaling Groups", icon: CopyPlus, category: "Compute", to: "/auto-scaling-groups" }, // EC2 Auto Scaling
  { label: "Functions", icon: Zap, category: "Compute", to: "/functions" }, // Lambda
  { label: "Scheduled Jobs", icon: CalendarClock, category: "Compute", to: "/scheduled-jobs" }, // EventBridge Scheduler / scheduled tasks

  // ── Front-end Web & Mobile ───────────────────────────────────────────────────
  { label: "Static Sites", icon: AppWindow, category: "Front-end Web & Mobile", to: "/staticsites" }, // Amplify

  // ── Machine Learning (SageMaker) [MULTI] ─────────────────────────────────────
  {
    label: "Machine Learning",
    icon: BrainCircuit,
    category: "Machine Learning",
    to: "/models", // no /ml dashboard route yet → land on Models (AWS-style: first item)
    children: [
      { label: "Models", to: "/models", icon: BrainCircuit, matchPrefix: true },
      { label: "Training jobs", to: "/trainingjobs", icon: BrainCog, matchPrefix: true },
      { label: "Processing jobs", to: "/processing", icon: FlaskConical, matchPrefix: true },
      { label: "Tuning jobs", to: "/tuning", icon: Target, matchPrefix: true },
      { label: "Batch transform", to: "/batch-transform", icon: Layers, matchPrefix: true },
      { label: "Model registry", to: "/model-registry", icon: Package, matchPrefix: true },
      { label: "Model monitor", to: "/model-monitor", icon: Gauge, matchPrefix: true },
      { label: "Feature store", to: "/feature-store", icon: Table2, matchPrefix: true },
    ],
  },

  // ── Storage ──────────────────────────────────────────────────────────────────
  { label: "Buckets", icon: HardDrive, category: "Storage", to: "/buckets" }, // S3
  { label: "Volumes", icon: Disc3, category: "Storage", to: "/volumes" }, // EBS
  { label: "File Shares", icon: FolderTree, category: "Storage", to: "/fileshares" }, // EFS / FSx
  { label: "Snapshots", icon: Camera, category: "Storage", to: "/snapshots" }, // native unified snapshots

  // ── Database ─────────────────────────────────────────────────────────────────
  {
    // RDS — Databases + Proxies.
    label: "Databases",
    icon: Database,
    category: "Database",
    to: "/databases",
    children: [
      { label: "Databases", to: "/databases", icon: Database, matchPrefix: true },
      { label: "Database proxies", to: "/database-proxies", icon: DatabaseZap, matchPrefix: true },
    ],
  },
  { label: "Tables", icon: Table2, category: "Database", to: "/tables" }, // DynamoDB

  // ── Analytics ────────────────────────────────────────────────────────────────
  { label: "Query", icon: Search, category: "Analytics", to: "/queries" }, // Athena
  {
    // DMS / Glue-Studio-style visual data integration — the unified DataFlow canvas.
    // Migrations, Replications, Streams and Lineage gain their nav home here.
    label: "Data Flows",
    icon: Workflow,
    category: "Analytics",
    to: "/dataflows",
    children: [
      { label: "Data flows", to: "/dataflows", icon: Workflow, matchPrefix: true },
      { label: "Migrations", to: "/migrations", icon: ArrowRightLeft, matchPrefix: true },
      { label: "Replications", to: "/replications", icon: GitCompareArrows, matchPrefix: true },
      { label: "Streams", to: "/streams", icon: Radio, matchPrefix: true },
      { label: "Lineage", to: "/lineage", icon: Waypoints, matchPrefix: true },
    ],
  },

  // ── Application Integration ──────────────────────────────────────────────────
  {
    // Step Functions — State machines; executions are viewed under a state machine
    // (/executions/* has no list route, so it is resolved via routePrefixes only).
    label: "State Machines",
    icon: Route,
    category: "Application Integration",
    to: "/statemachines",
    children: [
      { label: "State machines", to: "/statemachines", icon: Route, matchPrefix: true },
    ],
    routePrefixes: ["/executions"],
  },
  { label: "HTTP APIs", icon: Webhook, category: "Application Integration", to: "/http-apis" }, // API Gateway
  { label: "GraphQL", icon: Waypoints, category: "Application Integration", to: "/graphql" }, // AppSync
  { label: "Queues", icon: Send, category: "Application Integration", to: "/queues" }, // SQS / SNS

  // ── Customer Engagement ──────────────────────────────────────────────────────
  { label: "Email Senders", icon: Mail, category: "Customer Engagement", to: "/emailsenders" }, // SES

  // ── Networking & Content Delivery (VPC) [MULTI] ──────────────────────────────
  {
    label: "VPC",
    icon: Network,
    category: "Networking & Content Delivery",
    to: "/networking",
    children: [
      { label: "VPC dashboard", to: "/networking", icon: LayoutDashboard, matchPrefix: true },
      { label: "Your VPCs", to: "/vpcs", icon: Network, matchPrefix: true },
      { label: "Subnets", to: "/subnets", icon: Boxes, matchPrefix: true },
      { label: "NAT gateways", to: "/nat-gateways", icon: Waypoints, matchPrefix: true },
      { label: "Elastic IPs", to: "/elastic-ips", icon: Globe, matchPrefix: true },
      { label: "Transit gateways", to: "/transit-gateways", icon: Share2, matchPrefix: true },
      { label: "Flow logs", to: "/flow-logs", icon: ScrollText, matchPrefix: true },
      { label: "Security groups", to: "/security-groups", icon: Shield, matchPrefix: true },
    ],
  },

  // ── Security, Identity & Compliance ──────────────────────────────────────────
  {
    // IAM [MULTI] — the canonical "service you enter". AWS sub-nav order.
    // Identity providers & Account settings are net-new (no route yet) — omitted
    // until their pages exist, rather than shipping a link that 404s.
    label: "IAM",
    icon: Fingerprint,
    category: "Security, Identity & Compliance",
    to: "/iam",
    children: [
      { label: "Dashboard", to: "/iam", icon: LayoutDashboard, matchPrefix: true },
      { label: "User groups", to: "/groups", icon: UsersRound, matchPrefix: true },
      { label: "Users", to: "/users", icon: Users, matchPrefix: true },
      { label: "Roles", to: "/roles", icon: ShieldCheck, matchPrefix: true },
      { label: "Policies", to: "/policies", icon: FileText, matchPrefix: true },
      { label: "Grants", to: "/grants", icon: Clock, matchPrefix: true }, // native "Temporary access"
      { label: "Access review", to: "/access-review", icon: ClipboardCheck, matchPrefix: true }, // native "Access reports"
      { label: "Policy simulator", to: "/policy-simulator", icon: FlaskConical, matchPrefix: true },
    ],
  },
  { label: "Encryption Keys", icon: KeyRound, category: "Security, Identity & Compliance", to: "/encryption" }, // KMS
  { label: "User Pools", icon: IdCard, category: "Security, Identity & Compliance", to: "/user-pools" }, // Cognito
  { label: "Active Directory", icon: Building2, category: "Security, Identity & Compliance", to: "/directories" }, // Directory Service
  { label: "Certificate Authority", icon: FileBadge, category: "Security, Identity & Compliance", to: "/pki" }, // ACM / Private CA (added to nav)
  { label: "Data Classification", icon: Tags, category: "Security, Identity & Compliance", to: "/data-classification" }, // Macie
  { label: "Attestation", icon: BadgeCheck, category: "Security, Identity & Compliance", to: "/attestation" }, // Audit Manager (native)

  // ── Management & Governance ──────────────────────────────────────────────────
  { label: "Monitoring", icon: LineChart, category: "Management & Governance", to: "/monitoring" }, // CloudWatch
  { label: "Cost Explorer", icon: DollarSign, category: "Management & Governance", to: "/cost" }, // Cost Explorer / Billing
  { label: "Parameters", icon: SlidersHorizontal, category: "Management & Governance", to: "/parameters" }, // SSM Parameter Store
  { label: "Audit", icon: ScrollText, category: "Management & Governance", to: "/audit" }, // CloudTrail
  { label: "Chaos", icon: Bomb, category: "Management & Governance", to: "/chaos", flag: "chaosUiEnabled" }, // FIS (flag-gated)

  // ── Cluster (open-infra native — no AWS analog) ──────────────────────────────
  { label: "Workloads", icon: Layers, category: "Cluster", to: "/workloads" },
  { label: "Nodes", icon: Server, category: "Cluster", to: "/nodes" },
  { label: "Network", icon: Globe, category: "Cluster", to: "/network" },
];

// ── Route matching / resolution ──────────────────────────────────────────────

/** Length of `to` if it is a prefix of `pathname` (exact or a "/"-boundary child), else -1. */
export function matchLen(pathname: string, to: string): number {
  if (to === "/") return pathname === "/" ? 1 : -1;
  if (pathname === to || pathname.startsWith(`${to}/`)) return to.length;
  return -1;
}

/** True when `to` owns the current path (used for active highlighting). */
export function isActive(pathname: string, to: string): boolean {
  return matchLen(pathname, to) >= 0;
}

/** All routes a service owns (landing + children + extra prefixes) for resolution. */
function serviceAnchors(svc: Service): string[] {
  return [svc.to, ...(svc.children?.map((c) => c.to) ?? []), ...(svc.routePrefixes ?? [])];
}

/**
 * Route → service resolution: given a pathname, find which service owns it (the
 * one with the longest-matching anchor route). Returns undefined for the home
 * dashboard and any unrooted path. This is what drives the shell's mode swap.
 */
export function serviceForPath(pathname: string): Service | undefined {
  let best: Service | undefined;
  let bestLen = -1;
  for (const svc of SERVICES) {
    for (const anchor of serviceAnchors(svc)) {
      const len = matchLen(pathname, anchor);
      if (len > bestLen) {
        bestLen = len;
        best = svc;
      }
    }
  }
  return bestLen >= 0 ? best : undefined;
}

/**
 * The active sub-nav leaf within a multi service (longest-matching child), or
 * undefined for a flat service / an owned-but-unlisted route (e.g. /executions).
 */
export function leafForPath(pathname: string): NavItem | undefined {
  const svc = serviceForPath(pathname);
  if (!svc?.children) return undefined;
  let best: NavItem | undefined;
  let bestLen = -1;
  for (const child of svc.children) {
    const len = matchLen(pathname, child.to);
    if (len > bestLen) {
      bestLen = len;
      best = child;
    }
  }
  return bestLen >= 0 ? best : undefined;
}

/** A multi service is one you *enter* (it has a distinct sub-nav to swap to). */
export function isMultiService(svc: Service | undefined): boolean {
  return Boolean(svc?.children && svc.children.length > 0);
}

// ── Visibility ───────────────────────────────────────────────────────────────

/**
 * Whether a nav leaf is visible given runtime config. Items carrying a `flag`
 * (e.g. Chaos → chaosUiEnabled) appear only when that flag is true.
 */
export function navItemVisible(item: NavItem, config: AppConfig): boolean {
  return !item.flag || Boolean(config[item.flag]);
}

/** Whether a service is visible given runtime config (same flag rule). */
export function serviceVisible(service: Service, config: AppConfig): boolean {
  return !service.flag || Boolean(config[service.flag]);
}

// ── Flattened leaves (command palette + pin/recent store) ────────────────────

/**
 * Every leaf destination, flattened: the Dashboard, each multi service's sub-nav
 * children, and each flat service's list. Consumed by the ⌘K command palette
 * (which still lists all leaf routes) and the pin/recent path lookup. `section`
 * is a display hint: the parent service for a sub-nav child, the category for a
 * flat service.
 */
export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/", icon: LayoutDashboard },
  ...SERVICES.flatMap((svc) => {
    if (svc.children && svc.children.length > 0) {
      return svc.children.map((child) => ({ ...child, section: svc.label }));
    }
    return [
      {
        label: svc.label,
        to: svc.to,
        icon: svc.icon,
        section: svc.category,
        matchPrefix: true,
        ...(svc.flag ? { flag: svc.flag } : {}),
      } satisfies NavItem,
    ];
  }),
];
