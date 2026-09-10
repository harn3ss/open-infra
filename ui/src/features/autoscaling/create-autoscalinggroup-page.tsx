import { useNavigate } from "@tanstack/react-router";
import { CopyPlus } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { AUTOSCALINGGROUP_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: AutoScalingGroup. */
export function CreateAutoScalingGroupPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={AUTOSCALINGGROUP_CREATE.kind}
      crdName={AUTOSCALINGGROUP_CREATE.crdName}
      icon={<CopyPlus className="size-6 text-primary" />}
      title={`Create ${AUTOSCALINGGROUP_CREATE.kind}`}
      description={AUTOSCALINGGROUP_CREATE.description}
      sections={AUTOSCALINGGROUP_CREATE.sections}
      sizing={AUTOSCALINGGROUP_CREATE.sizing}
      uiSchema={AUTOSCALINGGROUP_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.autoscalinggroups(ns)}
      listPath={openinfraPaths.autoscalinggroups()}
      onCancel={() => navigate({ to: "/auto-scaling-groups" })}
      onCreated={(namespace, name) => navigate({ to: "/auto-scaling-groups/$namespace/$name", params: { namespace, name } })}
    />
  );
}
