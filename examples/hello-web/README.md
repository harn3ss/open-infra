# hello-web — open-infra example

The smallest possible open-infra app: a container that prints a greeting on
`:8080`. It exists to demonstrate the full DX loop end to end.

## Try it locally (no cluster)

```bash
docker build -t hello-web .
docker run --rm -p 8080:8080 -e GREETING="hi" hello-web
curl localhost:8080
```

## Deploy it with open-infra

1. Copy `infra.yaml` and `.github/workflows/deploy.yml` into your app repo.
2. Set repo secrets `OPENINFRA_GITOPS_REPO` and `OPENINFRA_TOKEN`.
3. `git push`. The Action builds the image, renders the `Application`, and
   commits it to your GitOps repo; Argo CD + Crossplane reconcile it into a
   running, autoscaling, HTTPS service.

Or, against a cluster you control directly:

```bash
../../cli/open-infra deploy      # applies infra.yaml to the cluster
../../cli/open-infra status
```

Uncomment the `database:` / `storage:` lines in `infra.yaml` to get a managed
Postgres and an object-storage bucket with credentials injected automatically.
