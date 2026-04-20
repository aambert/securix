<!--
SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# OpenBao secret prefetch

`securix.openbao` is a **standalone** NixOS module that runs a
single systemd oneshot service, `securix-openbao.service`,
authenticating against an [OpenBao](https://openbao.org/) (or
HashiCorp Vault) KV v2 mount at startup and writing the
configured secrets to well-known files under
`/run/openbao/secrets/<name>` (tmpfs, mode `0440`, group `keys`).

It is independent from any specific consumer. Log-shipper,
sshd-agent hooks, internal helper scripts — any NixOS unit — can
read from the output directory by ordering itself after
`securix-openbao.service`.

## Why prefetch rather than a long-running agent

- **Low coupling.** No sidecar process to supervise, no local
  socket / token cache to reason about.
- **Failures are loud.** If a secret is missing or the auth flow
  breaks, the oneshot unit fails — downstream services that
  `Wants=` it are held back, which is the desired failure mode
  for security-relevant pipelines.
- **Short-lived material works.** Every `systemctl restart` of a
  consumer (or `systemctl restart securix-openbao`) re-fetches.
  For rotating secrets, combine with a systemd timer.

The trade-off is that a KV fetch happens at every restart — if
that cost is prohibitive, swap in a `bao agent` sidecar via
additional systemd units; the output contract remains the same.

## Configuration

```nix
{
  securix.openbao = {
    enable = true;
    address = "https://bao.corp.local:8200";
    tlsCaFile = "/etc/ssl/certs/corp-ca.pem";

    # AppRole (recommended for machines) …
    roleIdFile   = "/run/keys/bao-role-id";
    secretIdFile = "/run/keys/bao-secret-id";
    # … or a static token as a fallback:
    # tokenFile = "/run/keys/bao-token";

    # Enterprise namespace is optional:
    # namespace = "my-ns";

    kvMount = "secret";    # default
    secrets = {
      os_password     = { path = "securix/opensearch"; field = "password"; };
      syslog_key_pass = { path = "securix/syslog";     field = "key_passphrase"; };
      # each writes to /run/openbao/secrets/<basename>
    };
  };
}
```

Assertions at evaluation time catch the two common
misconfigurations:

- `enable = true` with neither AppRole nor a static token set.
- `enable = true` with `secrets = { }` (the fetch unit would run
  but pull nothing).

## Consuming a fetched secret

Any consumer works by:

1. Pointing its `*File` option at a path under
   `/run/openbao/secrets/`.
2. Ordering its systemd unit after `securix-openbao.service`.

The log-shipper auto-detects paths in the output directory and
adds the ordering implicitly, so the minimum consumer config is:

```nix
{
  securix.o11y.logShipper.sinks.opensearch = {
    enable = true;
    endpoint = "https://opensearch.corp.local:9200";
    auth.user = "securix";
    auth.passwordFile = "/run/openbao/secrets/os_password";
  };
}
```

For a bespoke unit:

```nix
{
  systemd.services.my-consumer = {
    after = [ "securix-openbao.service" ];
    wants = [ "securix-openbao.service" ];
    serviceConfig.LoadCredential = [
      "api_token:/run/openbao/secrets/my_token"
    ];
  };
}
```

`LoadCredential` copies the file at consumer activation (as
root), so the consumer can run as any user / DynamicUser without
needing the `keys` group.

## Architecture

```
   ┌──────────────────────┐
   │ OpenBao / Vault      │
   │  KV v2 mount         │
   └──────────┬───────────┘
              │ AppRole or token (LoadCredential'd)
              ▼
   ┌──────────────────────────────────────┐
   │ securix-openbao.service              │
   │  Type=oneshot, RemainAfterExit=true  │
   │  ExecStart: fetch + write all        │
   │  secrets to /run/openbao/secrets/    │
   └──────────────────┬───────────────────┘
                      │ After=, Wants=
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   consumer 1    consumer 2     consumer N
   (log-shipper, app-X, any systemd unit)
```

## Limitations

- KV v2 only. KV v1 mounts can be added later.
- The fetch script uses `curl` + `jq` (already in the base
  closure); no direct dependency on the `bao` / `vault` CLI.
- Secrets vanish on reboot (tmpfs). Every restart re-auths
  against OpenBao — for short-TTL material this is the point,
  for long-lived bootstrap tokens consider a periodic
  `systemctl restart securix-openbao`.
- Token renewal is not implemented: this is a prefetch, not a
  long-running agent. The fetched material is expected to live
  as long as the consumer session or be re-fetched on restart.
