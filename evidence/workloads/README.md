# evidence/workloads/

Committed, machine-readable **workload health observations** — the last time a given cluster workload
was observed running healthy, captured as verifiable evidence rather than a narrative claim. Each file
is `<workload-name>.json` with:

| field | meaning |
|---|---|
| `name` | workload name |
| `namespace` | its namespace |
| `healthy` | `true` only when it was OBSERVED running healthy (not "the code is complete") |
| `evidence_level` | `verified` = a real observation of the running workload |
| `when` | UTC timestamp of the observation |
| `detail` | what was observed (job names, container exit codes, output markers) — enough to re-verify |

These are point-in-time observations of a self-hosted cluster; they carry no secrets and no
site-specific hostnames/IPs. A green checkmark on the code half of a fix is not the same as an
observation of the fixed workload running — these snapshots close that gap and keep it verifiable
later. (The drop-review tooling's `workload_health` answer reads the same `evidence/workloads/<name>.json`
shape.)
