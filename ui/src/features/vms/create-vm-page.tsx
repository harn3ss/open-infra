import { useNavigate } from "@tanstack/react-router";
import { Monitor } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { VIRTUALMACHINE_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page create for kind: VirtualMachine — schema-driven, on the shared CreatePage. */
export function CreateVmPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={VIRTUALMACHINE_CREATE.kind}
      crdName={VIRTUALMACHINE_CREATE.crdName}
      icon={<Monitor className="size-6 text-primary" />}
      title="Create VirtualMachine"
      description={VIRTUALMACHINE_CREATE.description}
      sections={VIRTUALMACHINE_CREATE.sections}
      uiSchema={VIRTUALMACHINE_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.virtualmachines(ns)}
      listPath={openinfraPaths.virtualmachines()}
      onCancel={() => navigate({ to: "/vms" })}
      onCreated={(namespace, name) =>
        navigate({ to: "/vms/$namespace/$name", params: { namespace, name } })
      }
    />
  );
}
