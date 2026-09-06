import { useMemo, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  Check,
  X,
  Loader2,
  Circle,
  AlertTriangle,
  RotateCcw,
  Undo2,
} from "lucide-react";
import { Wizard, WizardReview, type WizardStep } from "@/components/create/wizard";
import { ExpandableSection } from "@/components/create/expandable-section";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useFlash } from "@/components/common/flashbar";
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { ApiError, k8sCreate, k8sDelete } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";
import { cn } from "@/lib/utils";
import { VpcWizardPreview, type VpcPreviewModel } from "./vpc-wizard-preview";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const API_VERSION = `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`;

/* ----------------------------- IPv4 / CIDR utils ---------------------------- */

function ipToInt(ip: string): number | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const v = Number(p);
    if (v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}
function intToIp(n: number): string {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
}
function parseCidr(cidr: string): { base: number; prefix: number } | null {
  const m = cidr.trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!m) return null;
  const ip = ipToInt(m[1] ?? "");
  const prefix = Number(m[2] ?? "");
  if (ip == null || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { base: (ip & mask) >>> 0, prefix };
}
function cidrValid(cidr: string): boolean {
  return parseCidr(cidr) != null;
}
function ipInCidr(ip: string, cidr: string): boolean {
  const c = parseCidr(cidr);
  const n = ipToInt(ip);
  if (!c || n == null) return false;
  const mask = c.prefix === 0 ? 0 : (0xffffffff << (32 - c.prefix)) >>> 0;
  return ((n & mask) >>> 0) === c.base;
}
function rangesOverlap(a: string, b: string): boolean {
  const ca = parseCidr(a);
  const cb = parseCidr(b);
  if (!ca || !cb) return false;
  const aEnd = ca.base + 2 ** (32 - ca.prefix) - 1;
  const bEnd = cb.base + 2 ** (32 - cb.prefix) - 1;
  return ca.base <= bEnd && cb.base <= aEnd;
}
function chooseSubnetPrefix(supernet: string): number {
  const c = parseCidr(supernet);
  if (!c) return 24;
  return c.prefix < 24 ? 24 : Math.min(c.prefix + 4, 30);
}
function carve(supernet: string, count: number, start: number, prefix: number): string[] {
  const c = parseCidr(supernet);
  if (!c) return Array.from({ length: count }, () => "");
  const block = 2 ** (32 - prefix);
  return Array.from({ length: count }, (_, i) =>
    `${intToIp((c.base + (start + i) * block) >>> 0)}/${prefix}`,
  );
}
/** A sensible default internal IP for the NAT gateway — the last usable host of the public subnet. */
function defaultNatIp(cidr: string): string {
  const c = parseCidr(cidr);
  if (!c) return "";
  return intToIp((c.base + 2 ** (32 - c.prefix) - 2) >>> 0);
}

/* -------------------------------- Subnet plan ------------------------------- */

interface PlannedSubnet {
  key: string; // stable across prefix changes, keys the overrides map
  name: string;
  cidr: string;
  isPublic: boolean;
}

function buildAutoSubnets(
  prefix: string,
  planningCidr: string,
  pub: number,
  priv: number,
): PlannedSubnet[] {
  const sp = chooseSubnetPrefix(planningCidr);
  const cidrs = carve(planningCidr, pub + priv, 0, sp);
  const out: PlannedSubnet[] = [];
  for (let i = 0; i < pub; i++)
    out.push({ key: `public-${i + 1}`, name: `${prefix}-subnet-public-${i + 1}`, cidr: cidrs[i] ?? "", isPublic: true });
  for (let i = 0; i < priv; i++)
    out.push({ key: `private-${i + 1}`, name: `${prefix}-subnet-private-${i + 1}`, cidr: cidrs[pub + i] ?? "", isPublic: false });
  return out;
}

/* --------------------------------- Progress -------------------------------- */

type StepStatus = "pending" | "running" | "done" | "error";
interface ProgressRow {
  id: string;
  label: string;
  status: StepStatus;
}
interface PlanStep {
  id: string;
  label: string;
  listPath: string;
  manifest: K8sObject;
  rollbackPath: string;
}

/* ================================ The wizard =============================== */

export function CreateVpcAndMorePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const flash = useFlash();
  const { scoped } = useNamespace();

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = useMemo(
    () => nsWatch.items.map((n) => n.metadata.name).filter(Boolean).sort() as string[],
    [nsWatch.items],
  );

  // ── form state ─────────────────────────────────────────────────────────────
  const [step, setStep] = useState(0);
  const [prefix, setPrefix] = useState("");
  const [namespace, setNamespace] = useState(scoped ?? "default");
  const [planningCidr, setPlanningCidr] = useState("10.0.0.0/16");
  const [publicCount, setPublicCount] = useState(2);
  const [privateCount, setPrivateCount] = useState(2);
  const [overrides, setOverrides] = useState<Record<string, { name?: string; cidr?: string }>>({});
  const [natEnabled, setNatEnabled] = useState(false);
  const [internalIp, setInternalIp] = useState("");
  const [egressPublicIp, setEgressPublicIp] = useState("");
  const [eipEnabled, setEipEnabled] = useState(false);
  const [eipAddress, setEipAddress] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  // ── derived ──────────────────────────────────────────────────────────────
  const vpcName = prefix ? `${prefix}-vpc` : "";
  const natName = prefix ? `${prefix}-nat` : "";
  const eipName = prefix ? `${prefix}-eip` : "";

  const autoSubnets = useMemo(
    () => buildAutoSubnets(prefix || "app", planningCidr, publicCount, privateCount),
    [prefix, planningCidr, publicCount, privateCount],
  );
  const subnets = useMemo<PlannedSubnet[]>(
    () =>
      autoSubnets.map((s) => ({
        ...s,
        name: overrides[s.key]?.name ?? s.name,
        cidr: overrides[s.key]?.cidr ?? s.cidr,
      })),
    [autoSubnets, overrides],
  );
  const firstPublic = subnets.find((s) => s.isPublic);
  const privateCidrs = subnets.filter((s) => !s.isPublic).map((s) => s.cidr);
  const effectiveInternalIp = internalIp.trim() || (firstPublic ? defaultNatIp(firstPublic.cidr) : "");
  const hasDefaultRoute = natEnabled && Boolean(firstPublic);

  const setOverride = (key: string, patch: { name?: string; cidr?: string }) =>
    setOverrides((o) => ({ ...o, [key]: { ...o[key], ...patch } }));

  // ── live preview model ──────────────────────────────────────────────────────
  const preview = useMemo<VpcPreviewModel>(
    () => ({
      vpcName: vpcName || "vpc",
      planningCidr,
      subnets: subnets.map(({ name, cidr, isPublic }) => ({ name, cidr, isPublic })),
      nat: natEnabled ? { name: natName || "nat", internalIp: effectiveInternalIp } : null,
      eip: natEnabled && eipEnabled ? { name: eipName || "eip", address: eipAddress.trim() || "auto-allocated" } : null,
      hasDefaultRoute,
    }),
    [vpcName, planningCidr, subnets, natEnabled, natName, effectiveInternalIp, eipEnabled, eipName, eipAddress, hasDefaultRoute],
  );

  // ── validation (never disables the primary — validate on Next/submit) ───────
  function validateStep(i: number): boolean {
    const e: Record<string, string> = {};
    if (i === 0) {
      if (!prefix.trim()) e.prefix = "A name prefix is required.";
      else if (!RFC1123.test(prefix)) e.prefix = "Lowercase letters, numbers and hyphens; must start/end alphanumeric.";
      else if (prefix.length > 40) e.prefix = "Keep the prefix short (≤ 40 chars) — it prefixes every child name.";
      if (!namespace) e.namespace = "Choose a namespace.";
      if (!cidrValid(planningCidr)) e.cidr = "Enter a valid IPv4 CIDR, e.g. 10.0.0.0/16.";
    }
    if (i === 1) {
      if (publicCount + privateCount < 1) e.subnets = "Add at least one subnet.";
      subnets.forEach((s) => {
        if (!RFC1123.test(s.name)) e[`sn-name-${s.key}`] = "Invalid name.";
        if (!cidrValid(s.cidr)) e[`sn-cidr-${s.key}`] = "Invalid CIDR.";
      });
      // pairwise overlap / duplicate check across valid CIDRs
      for (let a = 0; a < subnets.length; a++) {
        for (let b = a + 1; b < subnets.length; b++) {
          const sa = subnets[a];
          const sb = subnets[b];
          if (!sa || !sb) continue;
          if (cidrValid(sa.cidr) && cidrValid(sb.cidr) && rangesOverlap(sa.cidr, sb.cidr)) {
            e[`sn-cidr-${sb.key}`] = `Overlaps ${sa.name}.`;
          }
        }
      }
    }
    if (i === 2 && natEnabled) {
      if (!firstPublic) e.nat = "A NAT gateway needs at least one public subnet — add one on the Subnets step.";
      else if (!ipToInt(effectiveInternalIp)) e.internalIp = "Enter a valid IPv4 address for the gateway's internal leg.";
      else if (!ipInCidr(effectiveInternalIp, firstPublic.cidr)) e.internalIp = `Must be an address inside ${firstPublic.name} (${firstPublic.cidr}).`;
      if (egressPublicIp.trim() && !ipToInt(egressPublicIp)) e.egressPublicIp = "Enter a valid IPv4 address, or leave blank to auto-allocate.";
      if (eipEnabled && eipAddress.trim() && !ipToInt(eipAddress)) e.eipAddress = "Enter a valid IPv4 address, or leave blank to auto-allocate.";
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  // ── ordered multi-object create ─────────────────────────────────────────────
  const [phase, setPhase] = useState<"form" | "running" | "error" | "done">("form");
  const [progress, setProgress] = useState<ProgressRow[]>([]);
  const [failMsg, setFailMsg] = useState<string | null>(null);
  const planRef = useRef<PlanStep[]>([]);
  const createdRef = useRef<{ label: string; path: string }[]>([]);

  function buildPlan(): PlanStep[] {
    const plan: PlanStep[] = [];
    // 1) the Vpc — with the default route baked in when a NAT is planned (the
    //    NAT internalIp is a value we chose up front, so no post-create PATCH race).
    const vpcSpec: Record<string, unknown> = {};
    if (hasDefaultRoute) vpcSpec.routes = [{ cidr: "0.0.0.0/0", nextHop: effectiveInternalIp }];
    plan.push({
      id: "vpc",
      label: `VPC ${vpcName}`,
      listPath: openinfraPaths.vpcs(namespace),
      manifest: { apiVersion: API_VERSION, kind: "Vpc", metadata: { name: vpcName, namespace }, spec: vpcSpec },
      rollbackPath: openinfraPaths.vpc(namespace, vpcName),
    });
    // 2) each Subnet (public = private:false, private = private:true)
    subnets.forEach((s) => {
      plan.push({
        id: `subnet-${s.key}`,
        label: `Subnet ${s.name}`,
        listPath: openinfraPaths.subnets(namespace),
        manifest: {
          apiVersion: API_VERSION,
          kind: "Subnet",
          metadata: { name: s.name, namespace },
          spec: { cidr: s.cidr, vpc: vpcName, private: !s.isPublic },
        },
        rollbackPath: openinfraPaths.subnet(namespace, s.name),
      });
    });
    // 3) the NAT gateway (border device: NAT egress + internet-gateway role)
    if (natEnabled && firstPublic) {
      const egress: Record<string, unknown> = {};
      if (privateCidrs.length) egress.sourceCidrs = privateCidrs;
      if (egressPublicIp.trim()) egress.publicIp = egressPublicIp.trim();
      const natSpec: Record<string, unknown> = {
        vpc: vpcName,
        subnet: firstPublic.name,
        internalIp: effectiveInternalIp,
      };
      if (Object.keys(egress).length) natSpec.egress = egress;
      plan.push({
        id: "nat",
        label: `NAT gateway ${natName}`,
        listPath: openinfraPaths.natgateways(namespace),
        manifest: { apiVersion: API_VERSION, kind: "NatGateway", metadata: { name: natName, namespace }, spec: natSpec },
        rollbackPath: openinfraPaths.natgateway(namespace, natName),
      });
      // 4) the Elastic IP hosted on that gateway
      if (eipEnabled) {
        const eipSpec: Record<string, unknown> = { natGateway: natName };
        if (eipAddress.trim()) eipSpec.address = eipAddress.trim();
        plan.push({
          id: "eip",
          label: `Elastic IP ${eipName}`,
          listPath: openinfraPaths.elasticips(namespace),
          manifest: { apiVersion: API_VERSION, kind: "ElasticIp", metadata: { name: eipName, namespace }, spec: eipSpec },
          rollbackPath: openinfraPaths.elasticip(namespace, eipName),
        });
      }
    }
    return plan;
  }

  const setStatus = (id: string, status: StepStatus) =>
    setProgress((rows) => rows.map((r) => (r.id === id ? { ...r, status } : r)));

  async function runFrom(plan: PlanStep[], startIdx: number) {
    setPhase("running");
    setFailMsg(null);
    for (let i = startIdx; i < plan.length; i++) {
      const s = plan[i];
      if (!s) continue;
      setStatus(s.id, "running");
      try {
        await k8sCreate(s.listPath, s.manifest);
        createdRef.current.push({ label: s.label, path: s.rollbackPath });
        setStatus(s.id, "done");
      } catch (err) {
        // On a retry the object may already exist — treat that as success.
        if (err instanceof ApiError && err.status === 409) {
          createdRef.current.push({ label: s.label, path: s.rollbackPath });
          setStatus(s.id, "done");
          continue;
        }
        setStatus(s.id, "error");
        const msg = err instanceof ApiError ? err.message : `Failed to create ${s.label}.`;
        setFailMsg(msg);
        setPhase("error");
        flash.error(
          `Stopped at ${s.label}: ${msg}` +
            (createdRef.current.length ? ` ${createdRef.current.length} resource(s) already created — retry, or roll back.` : ""),
          { id: "vpc-wizard" },
        );
        return;
      }
    }
    // all green
    setPhase("done");
    flash.success(`Created VPC ${vpcName} and its ${plan.length - 1} associated resource(s).`, { id: "vpc-wizard" });
    void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.vpcs()) });
    navigate({ to: "/vpcs/$namespace/$name", params: { namespace, name: vpcName } });
  }

  async function rollbackCreated() {
    for (const c of [...createdRef.current].reverse()) {
      try {
        await k8sDelete(c.path);
      } catch {
        /* best-effort cleanup */
      }
    }
    createdRef.current = [];
  }

  async function handleSubmit() {
    if (phase === "error") {
      // resume from the first step that isn't done yet
      const idx = progress.findIndex((r) => r.status !== "done");
      await runFrom(planRef.current, idx < 0 ? planRef.current.length : idx);
      return;
    }
    // fresh submit: re-validate everything, jumping to the first broken step
    for (const i of [0, 1, 2]) {
      if (!validateStep(i)) {
        setStep(i);
        return;
      }
    }
    if (createdRef.current.length) await rollbackCreated(); // clear any prior aborted attempt
    const plan = buildPlan();
    planRef.current = plan;
    createdRef.current = [];
    setProgress(plan.map((s) => ({ id: s.id, label: s.label, status: "pending" as StepStatus })));
    await runFrom(plan, 0);
  }

  // Going back to edit after a terminal run returns to a clean editing state; a
  // fresh submit rolls back any orphaned resources before recreating (see handleSubmit).
  function handleNavigate(idx: number) {
    if (idx !== steps.length - 1 && (phase === "error" || phase === "done")) {
      setPhase("form");
      setProgress([]);
      setFailMsg(null);
    }
    setStep(idx);
  }

  async function doRollback() {
    await rollbackCreated();
    setPhase("form");
    setProgress([]);
    setFailMsg(null);
    flash.info("Rolled back the resources this wizard created.", { id: "vpc-wizard", autoDismiss: 6000 });
  }

  // ── steps ──────────────────────────────────────────────────────────────────
  const steps: WizardStep[] = [
    {
      title: "VPC settings",
      description: "Name and plan the address space. The prefix names every resource this wizard creates.",
      content: (
        <div className="space-y-5">
          <Field label="Name prefix" htmlFor="w-prefix" error={errors.prefix}>
            <Input
              id="w-prefix"
              value={prefix}
              onChange={(ev) => setPrefix(ev.target.value)}
              placeholder="prod"
              autoFocus
            />
            {prefix && RFC1123.test(prefix) ? (
              <p className="text-xs text-muted-foreground">
                Creates <code>{vpcName}</code>, <code>{prefix}-subnet-public-1</code>…
                {natEnabled ? (
                  <>
                    , <code>{natName}</code>
                    {eipEnabled ? <>, <code>{eipName}</code></> : null}
                  </>
                ) : null}
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">
                Auto-derives all child names (<code>&lt;prefix&gt;-vpc</code>, <code>&lt;prefix&gt;-subnet-public-1</code>, …).
              </p>
            )}
          </Field>

          <Field label="Namespace" htmlFor="w-ns" error={errors.namespace}>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="w-ns">
                <SelectValue placeholder="Namespace" />
              </SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">All created objects share this namespace.</p>
          </Field>

          <Field label="IPv4 CIDR block" htmlFor="w-cidr" error={errors.cidr}>
            <Input
              id="w-cidr"
              value={planningCidr}
              onChange={(ev) => setPlanningCidr(ev.target.value)}
              placeholder="10.0.0.0/16"
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Used to plan subnet ranges — open-infra defines VPC address space by its subnets, so this planning
              supernet is <strong>not stored</strong> on the VPC.
            </p>
          </Field>
        </div>
      ),
    },
    {
      title: "Subnets",
      description: "Choose how many public and private subnets to carve from the planning CIDR.",
      content: (
        <div className="space-y-5">
          {errors.subnets ? <p className="text-sm text-destructive">{errors.subnets}</p> : null}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Number of public subnets" htmlFor="w-pub">
              <CountSelect id="w-pub" value={publicCount} onChange={setPublicCount} />
              <p className="text-xs text-muted-foreground">Public = reachable in/out (private: false).</p>
            </Field>
            <Field label="Number of private subnets" htmlFor="w-priv">
              <CountSelect id="w-priv" value={privateCount} onChange={setPrivateCount} />
              <p className="text-xs text-muted-foreground">Private = OVN-isolated by default (private: true).</p>
            </Field>
          </div>

          <ExpandableSection title="Customize subnet CIDRs" count={subnets.length}>
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground">
                Auto-carved from the planning CIDR (public first, then private). Override any name or range —
                overlaps are flagged.
              </p>
              {subnets.map((s) => (
                <div key={s.key} className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1fr_auto] sm:items-start">
                  <div className="space-y-1">
                    <Input
                      aria-label={`${s.key} name`}
                      value={s.name}
                      onChange={(ev) => setOverride(s.key, { name: ev.target.value })}
                    />
                    {errors[`sn-name-${s.key}`] ? (
                      <p className="text-xs text-destructive">{errors[`sn-name-${s.key}`]}</p>
                    ) : null}
                  </div>
                  <div className="space-y-1">
                    <Input
                      aria-label={`${s.key} CIDR`}
                      value={s.cidr}
                      onChange={(ev) => setOverride(s.key, { cidr: ev.target.value })}
                      className="font-mono"
                    />
                    {errors[`sn-cidr-${s.key}`] ? (
                      <p className="text-xs text-destructive">{errors[`sn-cidr-${s.key}`]}</p>
                    ) : null}
                  </div>
                  <span
                    className={cn(
                      "inline-flex h-9 items-center justify-center rounded-md px-2 text-xs font-medium",
                      s.isPublic ? "bg-success/10 text-success" : "bg-primary/10 text-primary",
                    )}
                  >
                    {s.isPublic ? "public" : "private"}
                  </span>
                </div>
              ))}
              {Object.keys(overrides).length ? (
                <Button variant="outline" size="sm" onClick={() => setOverrides({})}>
                  <RotateCcw className="size-3.5" /> Reset to auto-carved ranges
                </Button>
              ) : null}
            </div>
          </ExpandableSection>
        </div>
      ),
    },
    {
      title: "NAT gateway",
      isOptional: true,
      description: "Optionally add a border gateway for internet egress and routable ingress.",
      content: (
        <div className="space-y-5">
          <fieldset className="space-y-2">
            <RadioRow
              name="nat"
              checked={!natEnabled}
              onChange={() => setNatEnabled(false)}
              label="None"
              hint="No internet egress. Private subnets stay isolated; public subnets still route within the VPC."
            />
            <RadioRow
              name="nat"
              checked={natEnabled}
              onChange={() => setNatEnabled(true)}
              label="One NAT gateway"
              hint="On this substrate one border gateway serves both internet egress (SNAT) and routable ingress — there is no separate internet-gateway object."
            />
          </fieldset>

          {errors.nat ? (
            <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-muted-foreground">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
              <span>{errors.nat}</span>
            </div>
          ) : null}

          {natEnabled ? (
            <div className="space-y-5 rounded-lg border border-border p-4">
              <p className="text-xs text-muted-foreground">
                Placed on the first public subnet
                {firstPublic ? <> (<code>{firstPublic.name}</code>)</> : null}. A default route{" "}
                <code>0.0.0.0/0 → {effectiveInternalIp || "internal IP"}</code> is added to the VPC's route table.
              </p>
              <Field label="Internal IP" htmlFor="w-internal" error={errors.internalIp}>
                <Input
                  id="w-internal"
                  value={internalIp}
                  onChange={(ev) => setInternalIp(ev.target.value)}
                  placeholder={firstPublic ? defaultNatIp(firstPublic.cidr) : "10.0.0.254"}
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  The gateway's leg in the public subnet — the next hop for the VPC default route. Blank uses{" "}
                  <code>{firstPublic ? defaultNatIp(firstPublic.cidr) : "the last usable host"}</code>.
                </p>
              </Field>
              <Field label="Egress public IP — optional" htmlFor="w-egress" error={errors.egressPublicIp}>
                <Input
                  id="w-egress"
                  value={egressPublicIp}
                  onChange={(ev) => setEgressPublicIp(ev.target.value)}
                  placeholder="auto-allocate"
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  SNAT source address for {privateCidrs.length ? `${privateCidrs.length} private subnet(s)` : "egress"}. Blank = auto.
                </p>
              </Field>

              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={eipEnabled}
                  onChange={(ev) => setEipEnabled(ev.target.checked)}
                />
                <span>
                  <span className="font-medium">Allocate an Elastic IP</span>
                  <span className="block text-xs text-muted-foreground">
                    A static public IP hosted on this gateway ({eipName || "<prefix>-eip"}). Associate it with a
                    workload later from the Elastic IPs page.
                  </span>
                </span>
              </label>
              {eipEnabled ? (
                <Field label="Elastic IP address — optional" htmlFor="w-eip" error={errors.eipAddress}>
                  <Input
                    id="w-eip"
                    value={eipAddress}
                    onChange={(ev) => setEipAddress(ev.target.value)}
                    placeholder="auto-allocate"
                    className="font-mono"
                  />
                </Field>
              ) : null}
            </div>
          ) : null}
        </div>
      ),
    },
    {
      title: "Review and create",
      content:
        phase === "form" ? (
          <WizardReview
            onEditStep={setStep}
            sections={[
              {
                title: "VPC settings",
                stepIndex: 0,
                pairs: [
                  { label: "Name prefix", value: prefix || "—" },
                  { label: "VPC name", value: vpcName || "—" },
                  { label: "Namespace", value: namespace },
                  { label: "Planning CIDR", value: planningCidr },
                ],
              },
              {
                title: "Subnets",
                stepIndex: 1,
                content: (
                  <ul className="space-y-1 text-sm">
                    {subnets.map((s) => (
                      <li key={s.key} className="flex items-center gap-2">
                        <span
                          className={cn(
                            "rounded px-1.5 text-[10px] font-medium uppercase",
                            s.isPublic ? "bg-success/10 text-success" : "bg-primary/10 text-primary",
                          )}
                        >
                          {s.isPublic ? "public" : "private"}
                        </span>
                        <span className="font-medium">{s.name}</span>
                        <code className="text-muted-foreground">{s.cidr}</code>
                      </li>
                    ))}
                    {subnets.length === 0 ? <li className="text-muted-foreground">No subnets.</li> : null}
                  </ul>
                ),
              },
              {
                title: "NAT gateway",
                stepIndex: 2,
                pairs: natEnabled
                  ? [
                      { label: "NAT gateway", value: natName },
                      { label: "Internal IP", value: effectiveInternalIp || "—" },
                      { label: "Default route", value: hasDefaultRoute ? `0.0.0.0/0 → ${effectiveInternalIp}` : "—" },
                      { label: "Egress public IP", value: egressPublicIp.trim() || "auto" },
                      { label: "Elastic IP", value: eipEnabled ? `${eipName} (${eipAddress.trim() || "auto"})` : "none" },
                    ]
                  : [{ label: "NAT gateway", value: "None" }],
              },
            ]}
          />
        ) : (
          <ProgressPanel
            rows={progress}
            phase={phase}
            failMsg={failMsg}
            createdCount={createdRef.current.length}
            onRetry={handleSubmit}
            onRollback={doRollback}
          />
        ),
    },
  ];

  return (
    <Wizard
      title="Create VPC and more"
      steps={steps}
      activeStepIndex={step}
      onNavigate={handleNavigate}
      onValidateStep={validateStep}
      onCancel={() => navigate({ to: "/vpcs" })}
      onSubmit={handleSubmit}
      submitLabel={phase === "error" ? "Retry" : "Create VPC"}
      submitting={phase === "running"}
      preview={<VpcWizardPreview model={preview} />}
    />
  );
}

/* -------------------------------- small parts ------------------------------- */

function Field({
  label,
  htmlFor,
  error,
  children,
}: {
  label: string;
  htmlFor?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
    </div>
  );
}

function CountSelect({ id, value, onChange }: { id?: string; value: number; onChange: (n: number) => void }) {
  return (
    <Select value={String(value)} onValueChange={(v) => onChange(Number(v))}>
      <SelectTrigger id={id}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {[0, 1, 2, 3, 4].map((n) => (
          <SelectItem key={n} value={String(n)}>{n}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function RadioRow({
  name,
  checked,
  onChange,
  label,
  hint,
}: {
  name: string;
  checked: boolean;
  onChange: () => void;
  label: string;
  hint: string;
}) {
  return (
    <label
      className={cn(
        "flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors",
        checked ? "border-primary bg-secondary" : "border-border hover:bg-secondary/50",
      )}
    >
      <input type="radio" name={name} checked={checked} onChange={onChange} className="mt-1" />
      <span>
        <span className="text-sm font-medium">{label}</span>
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
    </label>
  );
}

function ProgressPanel({
  rows,
  phase,
  failMsg,
  createdCount,
  onRetry,
  onRollback,
}: {
  rows: ProgressRow[];
  phase: "form" | "running" | "error" | "done";
  failMsg: string | null;
  createdCount: number;
  onRetry: () => void;
  onRollback: () => void;
}) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        There is no composite API object, so the console creates each resource in dependency order.
      </p>
      <ol className="space-y-2">
        {rows.map((r) => (
          <li key={r.id} className="flex items-center gap-3 text-sm">
            <StatusIcon status={r.status} />
            <span className={cn(r.status === "error" && "text-destructive", r.status === "pending" && "text-muted-foreground")}>
              {r.label}
            </span>
          </li>
        ))}
      </ol>

      {phase === "error" ? (
        <div className="space-y-3">
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <div className="space-y-1">
              <p>{failMsg ?? "A step failed."}</p>
              {createdCount > 0 ? (
                <p className="text-xs text-destructive/90">
                  {createdCount} resource(s) were already created. Retry to resume from the failed step, or roll back to
                  delete them.
                </p>
              ) : null}
            </div>
          </div>
          <div className="flex gap-3">
            <Button onClick={onRetry}>
              <RotateCcw className="size-4" /> Retry
            </Button>
            {createdCount > 0 ? (
              <Button variant="outline" onClick={onRollback}>
                <Undo2 className="size-4" /> Roll back created resources
              </Button>
            ) : null}
          </div>
        </div>
      ) : null}

      {phase === "done" ? (
        <p className="text-sm text-success">All resources created. Opening the VPC…</p>
      ) : null}
    </div>
  );
}

function StatusIcon({ status }: { status: StepStatus }) {
  if (status === "done") return <Check className="size-4 shrink-0 text-success" aria-label="done" />;
  if (status === "running") return <Loader2 className="size-4 shrink-0 animate-spin text-primary" aria-label="creating" />;
  if (status === "error") return <X className="size-4 shrink-0 text-destructive" aria-label="failed" />;
  return <Circle className="size-4 shrink-0 text-muted-foreground" aria-label="pending" />;
}
