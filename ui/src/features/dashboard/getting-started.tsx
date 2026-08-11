import { Link } from "@tanstack/react-router";
import { ArrowRight, Boxes, BrainCircuit, Rocket, Zap } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { LearnMore } from "@/components/help/learn-more";
import { docsUrl } from "@/lib/kind-docs";

/** One suggested first action. */
const STEPS = [
  {
    to: "/applications/new",
    icon: Boxes,
    title: "Launch an Application",
    body: "An autoscaling HTTPS service — add a database, buckets, and queues in one form.",
  },
  {
    to: "/functions/new",
    icon: Zap,
    title: "Deploy a Function",
    body: "Serverless, scale-to-zero HTTP — open-infra's Lambda. Scales 0→N→0 with traffic.",
  },
  {
    to: "/models/new",
    icon: BrainCircuit,
    title: "Serve a Model",
    body: "A GPU-backed, OpenAI-compatible endpoint from the curated catalog.",
  },
] as const;

/**
 * First-run onboarding. Shown on the dashboard only while the cluster has no
 * open-infra resources yet — a few high-value "create your first thing" paths
 * plus the quickstart, then it gets out of the way (AWS "Getting started" tile).
 */
export function GettingStarted() {
  return (
    <Card className="border-primary/30 bg-primary/[0.03]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Rocket className="size-4 text-primary" />
          Getting started
        </CardTitle>
        <CardDescription>
          Nothing here yet. Create your first resource — every form explains each
          field inline, with an <span className="font-medium">Info</span> panel
          and a <span className="font-medium">Learn more</span> link. Or read the{" "}
          <LearnMore href={docsUrl("quickstart.md")}>quickstart</LearnMore>.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {STEPS.map((s) => (
          <Link
            key={s.to}
            to={s.to}
            className="group flex flex-col gap-1.5 rounded-lg border border-border bg-card p-4 transition-colors hover:border-primary/40"
          >
            <div className="flex items-center justify-between">
              <s.icon className="size-5 text-primary" />
              <ArrowRight className="size-4 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
            </div>
            <div className="mt-1 text-sm font-medium">{s.title}</div>
            <div className="text-xs text-muted-foreground">{s.body}</div>
          </Link>
        ))}
      </CardContent>
    </Card>
  );
}
