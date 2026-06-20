import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { useConfig } from "@/lib/config-context";
import { oirn } from "@/lib/oirn";

/**
 * A copyable "Resource name" (OIRN) row for detail pages — the AWS-ARN analog.
 * Computes the OIRN from the cluster (runtime config) + the resource identity.
 * Drop it inside a Card's divided CardContent alongside other DetailRows.
 */
export function ResourceNameRow({
  kind,
  name,
  namespace,
}: {
  kind: string;
  name: string;
  namespace?: string;
}) {
  const { clusterName } = useConfig();
  const id = oirn({ kind, name, cluster: clusterName, namespace });
  return (
    <DetailRow label="Resource name">
      <span className="flex items-center gap-1">
        <code className="text-xs">{id}</code>
        <CopyButton value={id} />
      </span>
    </DetailRow>
  );
}
