import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { Network } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { k8sCreate } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type Vpc } from "@/types/k8s";

export function CreateVpcPage() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState("default");
  const [namespaces, setNamespaces] = useState("");

  const create = useMutation({
    mutationFn: () => {
      const spec: Vpc["spec"] = {};
      const nsList = namespaces.split(",").map((s) => s.trim()).filter(Boolean);
      if (nsList.length) spec.namespaces = nsList;
      const obj = {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Vpc",
        metadata: { name, namespace },
        spec,
      };
      return k8sCreate(openinfraPaths.vpcs(namespace), obj);
    },
    onSuccess: () => navigate({ to: "/vpcs/$namespace/$name", params: { namespace, name } }),
  });

  const valid = name.trim() !== "";

  return (
    <DetailShell backTo="/vpcs" backLabel="VPCs" icon={<Network className="size-5" />} title="New VPC" subtitle="An isolated network domain (kube-ovn)">
      <Card>
        <CardContent className="space-y-4 p-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="name">Name</Label>
              <Input id="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="prod-vpc" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="ns">Namespace</Label>
              <Input id="ns" value={namespace} onChange={(e) => setNamespace(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="nslist">Bound namespaces (optional)</Label>
            <Input id="nslist" value={namespaces} onChange={(e) => setNamespaces(e.target.value)} placeholder="team-a, team-b" />
            <p className="text-xs text-muted-foreground">Namespaces whose default subnet lives in this VPC. Subnets also reference it via their VPC field.</p>
          </div>
          {create.isError ? (
            <p className="text-sm text-destructive">{(create.error as Error)?.message ?? "Create failed"}</p>
          ) : null}
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => navigate({ to: "/vpcs" })}>Cancel</Button>
            <Button disabled={!valid || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? "Creating…" : "Create VPC"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </DetailShell>
  );
}
