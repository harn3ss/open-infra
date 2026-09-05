import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { LayoutGrid } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { k8sCreate } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type Subnet } from "@/types/k8s";

export function CreateSubnetPage() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState("default");
  const [cidr, setCidr] = useState("");
  const [vpc, setVpc] = useState("");
  const [priv, setPriv] = useState(true);
  const [allow, setAllow] = useState("");
  const [gateway, setGateway] = useState("");

  const create = useMutation({
    mutationFn: () => {
      const spec: Subnet["spec"] = { cidr };
      if (vpc.trim()) spec.vpc = vpc.trim();
      spec.private = priv;
      const allowList = allow.split(",").map((s) => s.trim()).filter(Boolean);
      if (allowList.length) spec.allowSubnets = allowList;
      if (gateway.trim()) spec.gateway = gateway.trim();
      const obj = {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Subnet",
        metadata: { name, namespace },
        spec,
      };
      return k8sCreate(openinfraPaths.subnets(namespace), obj);
    },
    onSuccess: () => navigate({ to: "/subnets/$namespace/$name", params: { namespace, name } }),
  });

  const valid = name.trim() !== "" && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(cidr.trim());

  return (
    <DetailShell backTo="/subnets" backLabel="Subnets" icon={<LayoutGrid className="size-5" />} title="New Subnet" subtitle="A topologically-isolated network segment (kube-ovn)">
      <Card>
        <CardContent className="space-y-4 p-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="name">Name</Label>
              <Input id="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="app-tier" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ns">Namespace</Label>
              <Input id="ns" value={namespace} onChange={(e) => setNamespace(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="cidr">CIDR</Label>
            <Input id="cidr" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.20.0.0/24" />
            <p className="text-xs text-muted-foreground">Must not overlap other subnets.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vpc">VPC (optional)</Label>
            <Input id="vpc" value={vpc} onChange={(e) => setVpc(e.target.value)} placeholder="leave blank for the default VPC (ovn-cluster)" />
          </div>
          <div className="space-y-1.5">
            <Label>Isolation</Label>
            <div className="flex gap-4 text-sm">
              <label className="flex items-center gap-2">
                <input type="radio" checked={priv} onChange={() => setPriv(true)} /> Private (OVN-isolated — default)
              </label>
              <label className="flex items-center gap-2">
                <input type="radio" checked={!priv} onChange={() => setPriv(false)} /> Public
              </label>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="allow">Allowed subnets (optional)</Label>
            <Input id="allow" value={allow} onChange={(e) => setAllow(e.target.value)} placeholder="10.21.0.0/24, 10.22.0.0/24" />
            <p className="text-xs text-muted-foreground">CIDRs allowed to reach this private subnet — the deliberate "allow from another subnet" hole.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="gw">Gateway (optional)</Label>
            <Input id="gw" value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder="defaults to the first usable address" />
          </div>
          {create.isError ? (
            <p className="text-sm text-destructive">{(create.error as Error)?.message ?? "Create failed"}</p>
          ) : null}
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => navigate({ to: "/subnets" })}>Cancel</Button>
            <Button disabled={!valid || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? "Creating…" : "Create Subnet"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </DetailShell>
  );
}
