/**
 * OIRN — open-infra Resource Name. A stable, AWS-ARN-style handle for any
 * resource, DERIVED from its Kubernetes identity (cluster + namespace + kind +
 * name) rather than stored, so it never drifts.
 *
 *   oirn:openinfra:<cluster>:<namespace>:<kind>/<name>
 *
 * Cluster-scoped resources (bucket, queue, node) leave the namespace segment
 * empty: oirn:openinfra:<cluster>::bucket/<name>
 */
export function oirn(opts: {
  kind: string;
  name: string;
  cluster?: string;
  namespace?: string;
}): string {
  const cluster = opts.cluster?.trim() || "local";
  const ns = opts.namespace ?? "";
  return `oirn:openinfra:${cluster}:${ns}:${opts.kind}/${opts.name}`;
}
