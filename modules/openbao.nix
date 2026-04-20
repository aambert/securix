# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
#
# SPDX-License-Identifier: MIT

# Standalone OpenBao / HashiCorp Vault secret prefetch.
#
# Activates a single oneshot systemd service `securix-openbao.service`
# that authenticates against an OpenBao (or Vault) KV v2 mount and
# writes the configured secrets to well-known files under
# `/run/openbao/secrets/<name>` (mode 0440, root:keys).
#
# Consumers do NOT depend on this module's code — they depend on
# its OUTPUT: any path under /run/openbao/secrets/ produced by the
# service. Use from any module via:
#
#   securix.openbao.enable    = true;
#   securix.openbao.address   = "https://bao.corp.local:8200";
#   securix.openbao.roleIdFile   = "/run/keys/bao-role-id";
#   securix.openbao.secretIdFile = "/run/keys/bao-secret-id";
#   securix.openbao.secrets.my_secret = {
#     path  = "securix/some-app";
#     field = "password";
#   };
#
#   # …then, in a consumer module:
#   services.my-app = {
#     after = [ "securix-openbao.service" ];
#     wants = [ "securix-openbao.service" ];
#     serviceConfig.LoadCredential = [
#       "password:/run/openbao/secrets/my_secret"
#     ];
#   };

{ config, lib, pkgs, ... }:
let
  cfg = config.securix.openbao;
  inherit (lib) mkEnableOption mkIf mkOption optionalString types;
in
{
  options.securix.openbao = {
    enable = mkEnableOption "OpenBao / Vault KV v2 secret prefetch";

    address = mkOption {
      type = types.str;
      example = "https://bao.corp.local:8200";
      description = "Base URL of the OpenBao / Vault server.";
    };

    namespace = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Enterprise namespace (sent as `X-Vault-Namespace`). Null for
        OSS OpenBao / Vault with no namespacing.
      '';
    };

    tlsCaFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        CA certificate used to verify the OpenBao endpoint. Null
        means trust the system store.
      '';
    };

    # ---- Authentication (exactly one of: AppRole pair, static token)
    roleIdFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to the AppRole `role_id` file. Paired with
        `secretIdFile`. Loaded via systemd's LoadCredential so the
        source file can be mode 0600 outside the service.
      '';
    };

    secretIdFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the AppRole `secret_id` file (LoadCredential).";
    };

    tokenFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Static token file — fallback when AppRole is not practical
        (CI, ad-hoc bootstrap). Prefer AppRole for long-lived
        workloads.
      '';
    };

    kvMount = mkOption {
      type = types.str;
      default = "secret";
      description = ''
        KV v2 mount point on the OpenBao server. Each secret path is
        resolved as `<address>/v1/<kvMount>/data/<path>` and the
        returned payload is decoded as `.data.data[<field>]`.
      '';
    };

    outputDir = mkOption {
      type = types.path;
      default = "/run/openbao/secrets";
      description = ''
        Directory under which fetched secrets are written. Created
        on service start as a tmpfs-like runtime directory so
        contents vanish on reboot. The service writes each file
        mode 0440, group "keys"; consumers that want to read them
        must either run as root or be in the "keys" group (e.g.
        via `SupplementaryGroups`). For systemd services using
        `LoadCredential`, the copy is always handled as root and
        mode doesn't matter on the consumer side.
      '';
    };

    secrets = mkOption {
      type = types.attrsOf (types.submodule ({ ... }: {
        options = {
          path = mkOption {
            type = types.str;
            example = "securix/opensearch";
            description = ''
              Secret path relative to `kvMount` (no leading `/`, no
              `data/` prefix — the module adds them). So
              `securix/opensearch` resolves to
              `/v1/<kvMount>/data/securix/opensearch`.
            '';
          };
          field = mkOption {
            type = types.str;
            default = "value";
            description = "Key inside the secret JSON payload to extract.";
          };
          mode = mkOption {
            type = types.strMatching "[0-7]{3,4}";
            default = "0440";
            description = "Mode of the written file.";
          };
        };
      }));
      default = { };
      example = lib.literalExpression ''
        {
          os_password     = { path = "securix/opensearch"; field = "password"; };
          syslog_key_pass = { path = "securix/syslog";     field = "key_passphrase"; };
        }
      '';
      description = ''
        Map of local basename → OpenBao location + output settings.
        Each entry is fetched at `securix-openbao.service` start
        and written to `<outputDir>/<basename>`.

        Failure on any secret stops service start — missing
        secrets never silently degrade to unauthenticated
        downstream operations.
      '';
    };
  };

  config = mkIf cfg.enable (
    let
      hasApprole = cfg.roleIdFile != null && cfg.secretIdFile != null;
      hasToken = cfg.tokenFile != null;

      fetchScript = pkgs.writeShellScript "securix-openbao-fetch" ''
        set -euo pipefail
        umask 0077

        SECDIR="${toString cfg.outputDir}"
        install -d -m 0750 -g keys "$SECDIR"

        CURL=(${pkgs.curl}/bin/curl --fail --silent --show-error)
        ${optionalString (cfg.tlsCaFile != null) ''
          CURL+=(--cacert "$CREDENTIALS_DIRECTORY/openbao_ca")
        ''}
        HDR_NS=()
        ${optionalString (cfg.namespace != null) ''
          HDR_NS=(-H "X-Vault-Namespace: ${cfg.namespace}")
        ''}

        # --- authenticate ---
        ${if hasApprole then ''
          RID="$(cat "$CREDENTIALS_DIRECTORY/openbao_role_id")"
          SID="$(cat "$CREDENTIALS_DIRECTORY/openbao_secret_id")"
          RESP="$("''${CURL[@]}" "''${HDR_NS[@]}" \
            -X POST "${cfg.address}/v1/auth/approle/login" \
            -H 'Content-Type: application/json' \
            -d "{\"role_id\":\"$RID\",\"secret_id\":\"$SID\"}")" || {
              echo "openbao: AppRole login failed" >&2; exit 1; }
          TOKEN="$(echo "$RESP" | ${pkgs.jq}/bin/jq -r .auth.client_token)"
        '' else ''
          TOKEN="$(cat "$CREDENTIALS_DIRECTORY/openbao_token")"
        ''}
        if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
          echo "openbao: empty token after auth; aborting" >&2
          exit 1
        fi

        # --- fetch secrets ---
        ${lib.concatMapStringsSep "\n" (name:
          let s = cfg.secrets.${name}; in ''
            RESP="$("''${CURL[@]}" "''${HDR_NS[@]}" \
              -H "X-Vault-Token: $TOKEN" \
              "${cfg.address}/v1/${cfg.kvMount}/data/${s.path}")" || {
                echo "openbao: fetch ${name} (${s.path}) failed" >&2; exit 1; }
            VAL="$(echo "$RESP" | ${pkgs.jq}/bin/jq -r '.data.data["${s.field}"] // empty')"
            if [ -z "$VAL" ]; then
              echo "openbao: ${s.path} has no field '${s.field}' (or empty)" >&2
              exit 1
            fi
            TMP="$(mktemp "$SECDIR/.${name}.XXXXXX")"
            printf '%s' "$VAL" > "$TMP"
            chmod ${s.mode} "$TMP"
            chgrp keys "$TMP" 2>/dev/null || true
            mv -f "$TMP" "$SECDIR/${name}"
          ''
        ) (lib.attrNames cfg.secrets)}
      '';
    in
    {
      assertions = [
        {
          assertion = hasApprole || hasToken;
          message = ''
            securix.openbao.enable = true but no authentication is
            configured. Set either `roleIdFile` + `secretIdFile`
            (AppRole) or `tokenFile` (static token).
          '';
        }
        {
          assertion = cfg.secrets != { };
          message = ''
            securix.openbao.enable = true but `securix.openbao.secrets`
            is empty — the fetch service would run but pull nothing.
            Populate the map or disable OpenBao.
          '';
        }
      ];

      # The "keys" group is conventional on NixOS for secret material
      # (agenix, vault-agent, …). Created here so the fetched files
      # can be dropped into it regardless of whether another module
      # already defines it; `mkDefault` is deliberately not used —
      # this option is declarative and additive.
      users.groups.keys = { };

      systemd.services.securix-openbao = {
        description = "OpenBao / Vault secret prefetch for Sécurix";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];

        serviceConfig = {
          Type = "oneshot";
          # `RemainAfterExit` lets downstream units key their
          # `After=` dependencies off a unit that never stays
          # "active" in the classical sense.
          RemainAfterExit = true;
          ExecStart = fetchScript;
          User = "root";
          Group = "root";

          LoadCredential =
            lib.optional (cfg.tlsCaFile != null)
              "openbao_ca:${toString cfg.tlsCaFile}"
            ++ lib.optional hasApprole
              "openbao_role_id:${toString cfg.roleIdFile}"
            ++ lib.optional hasApprole
              "openbao_secret_id:${toString cfg.secretIdFile}"
            ++ lib.optional hasToken
              "openbao_token:${toString cfg.tokenFile}";

          # Hardening — the fetch process only needs network egress
          # and the ability to write into /run/openbao/secrets.
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
          SystemCallFilter = [ "@system-service" "@network-io" ];
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          ReadWritePaths = [ (toString cfg.outputDir) "/run/openbao" ];
        };
      };
    }
  );
}
