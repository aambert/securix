<!--
SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Grafana dashboards for `securix.logShipper`

Ready-to-provision JSON dashboards for Grafana ≥ 10 with the
`grafana-opensearch-datasource` plugin (≥ 2.24).

| File | Dashboard | Time range | Refresh |
|------|-----------|------------|---------|
| [`securix-log-overview.json`](./securix-log-overview.json) | Sécurix — Log Overview | last 15 min | 5 s |
| [`securix-ssh-focus.json`](./securix-ssh-focus.json) | Sécurix — SSH Activity | last 1 h | 10 s |
| [`securix-audit.json`](./securix-audit.json) | Sécurix — Audit (ANSSI R73) | last 30 min | 5 s |

## Datasource expectations

The dashboards reference the datasource by its UID `opensearch`.
Provision it with:

```yaml
# /etc/grafana/provisioning/datasources/opensearch.yml
apiVersion: 1
datasources:
  - name: OpenSearch
    uid: opensearch
    type: grafana-opensearch-datasource
    access: proxy
    url: http://opensearch.corp.local:9200
    jsonData:
      database: 'securix-*'
      flavor: opensearch
      timeField: 'timestamp'
      version: '2.19.2'
      logMessageField: 'message'
      logLevelField: 'PRIORITY'
      pplEnabled: true
```

## Index + field expectations

Produced by `securix.logShipper` with `sinks.opensearch.index`
defaulting to `securix-%Y.%m.%d`. Key fields used by the panels:

- `timestamp` (date) — Vector's ingest timestamp
- `message` (text)
- `SYSLOG_IDENTIFIER.keyword`, `_SYSTEMD_UNIT.keyword`,
  `PRIORITY.keyword`, `host.keyword`
- `source_type.keyword` — either `"journald"` or `"auditd"`
- `audit_key.keyword`, `audit_type.keyword` — present only on
  records parsed from `/var/log/audit/audit.log` (requires
  `sources.auditFile.enable = true`)

## Provisioning the dashboards

```yaml
# /etc/grafana/provisioning/dashboards/securix.yml
apiVersion: 1
providers:
  - name: securix
    orgId: 1
    folder: Sécurix
    type: file
    options:
      path: /var/lib/grafana/dashboards/securix
```

Copy the three JSON files into
`/var/lib/grafana/dashboards/securix/`, set ownership readable by
Grafana, and restart. The dashboards land under the **Sécurix**
folder.
