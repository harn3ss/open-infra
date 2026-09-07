import { Link } from "@tanstack/react-router";
import {
  ArrowRight,
  Database,
  HardDrive,
  Hammer,
  Monitor,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { Widget } from "@/features/dashboard/widget";

/** The highest-value "create" flows, deep-linked to their create pages. */
const ACTIONS: {
  to: string;
  icon: LucideIcon;
  title: string;
  body: string;
}[] = [
  {
    to: "/vms/new",
    icon: Monitor,
    title: "Launch a virtual machine",
    body: "A KubeVirt VM — open-infra's EC2 instance.",
  },
  {
    to: "/buckets/new",
    icon: HardDrive,
    title: "Create a bucket",
    body: "S3-compatible object storage on MinIO.",
  },
  {
    to: "/functions/new",
    icon: Zap,
    title: "Deploy a function",
    body: "Serverless, scale-to-zero HTTP — our Lambda.",
  },
  {
    to: "/databases/new",
    icon: Database,
    title: "Create a database",
    body: "A managed Postgres cluster — our RDS.",
  },
];

/**
 * Build a solution — AWS Console Home's quick-start cards. Shortcuts into the
 * highest-value create flows so a new cluster is one click from its first
 * resource.
 */
export function BuildASolutionWidget({ className }: { className?: string }) {
  return (
    <Widget title="Build a solution" icon={Hammer} className={className}>
      <div className="grid flex-1 grid-cols-1 gap-3 sm:grid-cols-2">
        {ACTIONS.map((a) => (
          <Link
            key={a.to}
            to={a.to}
            className="group flex flex-col gap-1.5 rounded-lg border border-border p-4 transition-colors hover:border-primary/40 hover:bg-secondary/40"
          >
            <div className="flex items-center justify-between">
              <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <a.icon className="size-4" />
              </div>
              <ArrowRight className="size-4 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
            </div>
            <div className="mt-1 text-sm font-medium">{a.title}</div>
            <div className="text-xs text-muted-foreground">{a.body}</div>
          </Link>
        ))}
      </div>
    </Widget>
  );
}
