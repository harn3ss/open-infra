import { Bomb, Radio } from "lucide-react";
import { makeSimpleDetailPage } from "@/components/common/generic-detail-page";
import { openinfraPaths } from "@/lib/k8s-paths";

// spec is untyped on the generic object; read fields through a narrow cast.
const spec = (o: { spec?: unknown }) => (o.spec ?? {}) as Record<string, unknown>;

export const StreamDetailPage = makeSimpleDetailPage({
  kindLabel: "Stream",
  backTo: "/streams",
  backLabel: "Streams",
  queryKey: "stream",
  icon: <Radio className="size-5" />,
  getPath: openinfraPaths.stream,
  deletePath: openinfraPaths.stream,
});

export const FaultInjectionDetailPage = makeSimpleDetailPage({
  kindLabel: "Fault Injection",
  backTo: "/chaos",
  backLabel: "Chaos",
  queryKey: "faultinjection",
  icon: <Bomb className="size-5" />,
  getPath: openinfraPaths.faultinjection,
  deletePath: openinfraPaths.faultinjection,
  fields: [
    { label: "Type", value: (o) => String(spec(o).type ?? "—") },
    { label: "Duration", value: (o) => String(spec(o).duration ?? "—") },
  ],
});
