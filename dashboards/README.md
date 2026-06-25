# Observability (Prometheus + Grafana)

Tessera exposes a Prometheus metrics snapshot at **`GET /api/metrics`** (text
exposition format). It's behind the normal auth gate, so Prometheus scrapes it
with the API token as a bearer credential.

## Metrics

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `tessera_build_info` | gauge | `version`, `build` | Always 1; build identity as labels. |
| `tessera_devices_total` | gauge | — | Total known devices. |
| `tessera_devices` | gauge | `state` (new/expected/ignored) | Devices by review state. |
| `tessera_devices_online` | gauge | — | Devices with an active address. |
| `tessera_addresses` | gauge | `state` (active/stale/reserved/free) | Reconciled IPs by binding state. |
| `tessera_subnets_total` | gauge | — | Number of known subnets. |
| `tessera_subnet_addresses_used` | gauge | `cidr`, `name` | Addresses reconciled into a subnet. |
| `tessera_subnet_addresses_total` | gauge | `cidr`, `name` | Usable IPv4 capacity of a subnet. |
| `tessera_subnet_utilization_ratio` | gauge | `cidr`, `name` | Used / usable (0–1, IPv4). |
| `tessera_conflicts_open` | gauge | — | Open reconciliation conflicts. |
| `tessera_services_total` | gauge | — | Reachable services discovered. |
| `tessera_security_findings` | gauge | `severity` (high/medium/low) | Active (non-suppressed) exposed-service findings. |
| `tessera_observations_total` | gauge | — | Size of the append-only observation log. |
| `tessera_collector_up` | gauge | `collector` | 1 if the collector's last run succeeded. |
| `tessera_collector_last_run_seconds` | gauge | `collector` | Age of the collector's last run. |

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: tessera
    metrics_path: /api/metrics
    scheme: http              # use https if TLS is enabled
    authorization:
      type: Bearer
      credentials: "<TESSERA_API_TOKEN>"   # an admin API token
    static_configs:
      - targets: ["tessera-host:10404"]
```

Generate an API token under **Settings**, or set `TESSERA_API_TOKEN`.

## Grafana dashboard

Import [`grafana-tessera.json`](grafana-tessera.json) (Dashboards → New → Import)
and pick your Prometheus data source when prompted. Panels: device counts,
online, new/unexpected, open conflicts, high-severity findings, log size, device
mix, per-subnet utilization, and collector health.
