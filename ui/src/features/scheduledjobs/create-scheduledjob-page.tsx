import { useNavigate } from "@tanstack/react-router";
import { CalendarClock } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { SCHEDULEDJOB_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: ScheduledJob. */
export function CreateScheduledJobPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={SCHEDULEDJOB_CREATE.kind}
      crdName={SCHEDULEDJOB_CREATE.crdName}
      icon={<CalendarClock className="size-6 text-primary" />}
      title={`Create ${SCHEDULEDJOB_CREATE.kind}`}
      description={SCHEDULEDJOB_CREATE.description}
      sections={SCHEDULEDJOB_CREATE.sections}
      sizing={SCHEDULEDJOB_CREATE.sizing}
      uiSchema={SCHEDULEDJOB_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.scheduledjobs(ns)}
      listPath={openinfraPaths.scheduledjobs()}
      onCancel={() => navigate({ to: "/scheduled-jobs" })}
      onCreated={(namespace, name) => navigate({ to: "/scheduled-jobs/$namespace/$name", params: { namespace, name } })}
    />
  );
}
