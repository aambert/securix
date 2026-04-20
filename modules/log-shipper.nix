# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
#
# SPDX-License-Identifier: MIT

# Vector-based log shipper. Journald → OpenSearch (HTTP bulk) and/or
# syslog (RFC 5425 TLS / RFC 6587 plain TCP / RFC 3164 UDP) via a
# single long-running `vector` process.
#
# Why Vector and not journald-upload or rsyslog:
#   - Multiple sinks out of one source with independent back-pressure.
#   - Native TLS with LoadCredential-style secret handling.
#   - VRL transforms so the same pipeline feeds OpenSearch's bulk
#     endpoint and a syslog collector that expects RFC 5424 framing.
#   - `securix.o11y.logs` (services.journald.upload) is kept as a
#     minimal fallback; this module is opt-in and orthogonal.

{ config, lib, pkgs, ... }:
let
  cfg = config.securix.logShipper;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    optionalAttrs
    optionalString
    types
    ;
in
{
  options.securix.logShipper = {
    package = mkOption {
      type = types.package;
      default = pkgs.vector;
      defaultText = lib.literalExpression "pkgs.vector";
      description = "Vector derivation used by the shipper service.";
    };

    sources = {
      units = mkOption {
        type = types.listOf types.str;
        default = [
          "auditd.service"
          "sshd.service"
          "sudo.service"
          "systemd-logind.service"
        ];
        example = [ "auditd.service" ];
        description = ''
          Systemd units whose journal entries are captured.

          Default is a security-relevant set (auditd, sshd, sudo,
          logind). Set to `[ ]` to ingest the whole journal (noisy on
          a workstation; prefer an explicit list).
        '';
      };

      currentBootOnly = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Skip entries from previous boots. Keeps restarts from
          replaying the historical journal into the collector.
        '';
      };

      auditFile = {
        enable = mkEnableOption "tail the auditd log file (/var/log/audit/audit.log) in addition to journald";

        path = mkOption {
          type = types.path;
          default = "/var/log/audit/audit.log";
          description = ''
            Path to the auditd log file. Vector tails it with a
            `file` source and parses the `type=...`, `msg=audit(…)`
            and `key="..."` fields into `audit_type`, `audit_ts`,
            `audit_seq` and `audit_key`. Useful because auditd
            writes directly to this file and does not always route
            to journald.
          '';
        };
      };
    };

    filters = mkOption {
      type = types.listOf (types.submodule {
        options = {
          name = mkOption {
            type = types.strMatching "[a-zA-Z_][a-zA-Z0-9_]*";
            description = "Filter name (used as the Vector transform id; must be a valid identifier).";
          };
          dropIf = mkOption {
            type = types.str;
            description = ''
              VRL expression. Events for which the expression evaluates
              to `true` are DROPPED at the transform stage — never
              reach any sink. Use for source-side noise reduction
              (e.g. suppress debug-level entries, ignore a noisy unit).
            '';
            example = ''to_int(.PRIORITY) ?? 6 > 6'';
          };
        };
      });
      default = [ ];
      example = lib.literalExpression ''
        [
          { name = "drop_debug"; dropIf = "to_int(.PRIORITY) ?? 6 > 6"; }
          { name = "drop_cron";  dropIf = ".SYSLOG_IDENTIFIER == \"CRON\""; }
        ]
      '';
      description = ''
        Ordered list of source-side filter transforms. Each runs on
        the merged event stream after the built-in JSON parse, in
        declaration order. Events are dropped when `dropIf`
        evaluates to true; everything else falls through to the
        sinks.

        Filters run before routing, so a dropped event is dropped
        for every enabled sink. Per-sink routing differences
        require custom `extraSettings` on the sink.
      '';
    };

    sinks.opensearch = {
      enable = mkEnableOption "ship selected journal entries to OpenSearch";

      endpoint = mkOption {
        type = types.str;
        example = "https://opensearch.corp.local:9200";
        description = ''
          Base URL of the OpenSearch cluster. Any node works — Vector
          targets the `_bulk` endpoint internally.
        '';
      };

      index = mkOption {
        type = types.str;
        default = "securix-%Y.%m.%d";
        description = ''
          Strftime-templated index name. Daily indices are the
          OpenSearch idiom for time-series — keeps shard size
          manageable and rotation cheap.
        '';
      };

      auth = {
        user = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "OpenSearch basic-auth user. Null = no auth.";
        };
        passwordFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Path to a file containing the OpenSearch basic-auth
            password. Read through systemd LoadCredential at start
            and exposed to Vector via an environment variable —
            never embedded in the unit's command line.
          '';
        };
      };

      tls = {
        caFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            CA certificate used to verify the OpenSearch endpoint.
            Null = trust the system store.
          '';
        };
        verifyCertificate = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Verify the server certificate. Set to false ONLY for
            lab debugging — disabling verification on a channel
            that carries security logs undermines the whole point.
          '';
        };
      };

      extraSettings = mkOption {
        type = types.attrs;
        default = { };
        description = ''
          Additional Vector settings merged into the generated
          config (TOML-equivalent attrset). Use to tune buffer
          mode, add custom transforms, etc.
        '';
      };
    };

    sinks.syslog = {
      enable = mkEnableOption "ship selected journal entries to a syslog collector (default: RFC 5425 over TLS)";

      endpoint = mkOption {
        type = types.str;
        example = "syslog.corp.local:6514";
        description = ''
          host:port of the syslog collector. Port 6514 is the IANA
          assignment for RFC 5425 syslog-over-TLS; 514 is the
          legacy plain syslog port. Vector connects directly — no
          intermediate relay.
        '';
      };

      mode = mkOption {
        type = types.enum [ "tcp+tls" "tcp" "udp" ];
        # Default is plain TCP: matches the majority of on-premise
        # collectors (rsyslog `imtcp`, syslog-ng `network()` driver)
        # without extra CA / cert wiring. The module emits a loud
        # evaluation-time warning whenever the transport is not
        # `tcp+tls`, to make the cleartext choice explicit.
        # Other possibilities:
        #   - "tcp+tls" : RFC 5425 syslog over TLS (port 6514).
        #                 Preferred for security-relevant logs
        #                 crossing an untrusted network.
        #   - "udp"     : RFC 3164 BSD syslog on UDP.
        #                 Lossy, no encryption, legacy compat only.
        default = "tcp";
        description = ''
          Transport mode:

          - `tcp` (default): plain TCP (RFC 6587), no encryption.
            Wide compatibility, trusted local segment only. Emits
            an evaluation-time warning.
          - `tcp+tls`: RFC 5425 syslog over TLS. The only mode
            appropriate for shipping security-relevant logs across
            an untrusted network.
          - `udp`: legacy BSD syslog (RFC 3164 wire framing on UDP).
            Lossy, no encryption. Emits an evaluation-time warning.
        '';
      };

      appName = mkOption {
        type = types.str;
        default = "securix";
        description = ''
          APP-NAME field of the RFC 5424 header, used by SIEMs to
          route the stream into the right ingest pipeline. Keep
          short (RFC 5424 limit is 48 ASCII chars).
        '';
      };

      facility = mkOption {
        type = types.enum [
          "kern" "user" "mail" "daemon" "auth" "syslog" "lpr"
          "news" "uucp" "cron" "authpriv" "ftp"
          "local0" "local1" "local2" "local3"
          "local4" "local5" "local6" "local7"
        ];
        default = "authpriv";
        description = ''
          Syslog facility for the stream. `authpriv` (numeric 10) is
          the canonical choice for security-relevant events on a
          workstation and matches sshd's own facility. Switch to a
          `localN` if your SIEM routes a specific bucket.
        '';
      };

      framing = mkOption {
        type = types.enum [ "newline_delimited" "character_delimited" "length_delimited" "bytes" ];
        default = "newline_delimited";
        description = ''
          Framing on TCP / TLS. Default `newline_delimited` is
          compatible with rsyslog (`imtcp`), syslog-ng
          (`network()` driver), Splunk and most cloud SIEMs.
          Strict RFC 5425 octet-counting requires `bytes` framing
          plus a VRL transform that prepends the ASCII length —
          wire that via `extraSettings` if your collector demands
          it. Ignored when `mode = "udp"`.
        '';
      };

      tls = {
        caFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            CA certificate used to verify the syslog server's cert
            (only when `mode = "tcp+tls"`). Null = system store.
          '';
        };
        certFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Client certificate for mTLS (paired with `keyFile`).
            Only used when `mode = "tcp+tls"`.
          '';
        };
        keyFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Private key for mTLS. Loaded via systemd's
            LoadCredential — the file may be on a path the dynamic
            user cannot reach directly (e.g. /etc/ssl/private mode
            0640 root:ssl-cert); systemd bind-mounts it into the
            unit's namespace at startup and only the unit can
            read it.
          '';
        };
        keyPassFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Path to a file containing the passphrase for
            `keyFile` when encrypted. Same LoadCredential
            treatment.
          '';
        };
        verifyCertificate = mkOption {
          type = types.bool;
          default = true;
          description = "Verify the server certificate against the CA.";
        };
        verifyHostname = mkOption {
          type = types.bool;
          default = true;
          description = "Verify the server hostname matches its certificate SAN.";
        };
      };

      extraSettings = mkOption {
        type = types.attrs;
        default = { };
        description = ''
          Additional Vector settings merged into the generated
          config. Use to override buffer mode, add a second sink
          fan-out (e.g. mirror to a local file), etc.
        '';
      };
    };
  };

  config =
    let
      os = cfg.sinks.opensearch;
      sl = cfg.sinks.syslog;
      anyEnabled = os.enable || sl.enable;

      hasOSAuth = os.auth.user != null && os.auth.passwordFile != null;
      hasSlMtls = sl.tls.keyFile != null;
      hasSlKeyPass = sl.tls.keyPassFile != null;

      # Auto-detection of the standalone `securix.openbao` module's
      # output directory. Any sink file whose path lives inside this
      # directory is consumed from that module's prefetched output,
      # so the shipper unit must order itself after the prefetch.
      openbaoOutputDir = toString (config.securix.openbao.outputDir or "/run/openbao/secrets");
      pathInOpenbao = p: p != null && lib.hasPrefix (openbaoOutputDir + "/") (toString p);
      anyOpenbaoSecret =
        pathInOpenbao os.auth.passwordFile
        || pathInOpenbao sl.tls.keyFile
        || pathInOpenbao sl.tls.keyPassFile;

      # RFC 5424 facility name → numeric code (priority byte is
      # facility * 8 + severity).
      facilityCode = name: {
        kern = 0; user = 1; mail = 2; daemon = 3; auth = 4;
        syslog = 5; lpr = 6; news = 7; uucp = 8; cron = 9;
        authpriv = 10; ftp = 11;
        local0 = 16; local1 = 17; local2 = 18; local3 = 19;
        local4 = 20; local5 = 21; local6 = 22; local7 = 23;
      }.${name};

      credDir = "/run/credentials/securix-log-shipper.service";

      # Merge parsed event stream as the single upstream for sinks.
      # If filters are declared we chain a per-filter `filter`
      # transform; `filterChain` names the final stage consumed by
      # the sinks.
      filterChain =
        if cfg.filters == [ ] then "securix_parse"
        else "securix_filter_${toString (builtins.length cfg.filters)}";

      filterTransforms = lib.listToAttrs (
        lib.imap1
          (i: f: {
            name = "securix_filter_${toString i}";
            value = {
              type = "filter";
              inputs = [ (if i == 1 then "securix_parse" else "securix_filter_${toString (i - 1)}") ];
              # `filter` KEEPS events matching `condition`; the
              # user-facing knob is `dropIf`, so we negate.
              condition = "!(${f.dropIf})";
            };
          })
          cfg.filters
      );

      baseConfig = lib.recursiveUpdate (lib.recursiveUpdate {
        data_dir = "/var/lib/vector";

        # journald + optional auditd file source. Vector parses the
        # audit record header into audit_type / audit_ts / audit_seq /
        # audit_key; plain journald events still flow through the
        # same parse stage below.
        sources = {
          securix_journal = {
            type = "journald";
            current_boot_only = cfg.sources.currentBootOnly;
          } // optionalAttrs (cfg.sources.units != [ ]) {
            include_units = cfg.sources.units;
          };
        } // optionalAttrs cfg.sources.auditFile.enable {
          securix_audit_file = {
            type = "file";
            include = [ (toString cfg.sources.auditFile.path) ];
            read_from = "beginning";
          };
        };

        # Best-effort JSON parse on both sources: unit stdout that is
        # structured JSON gets its keys merged; auditd records get
        # their `type=...`, `msg=audit(ts:seq)` header and `key="…"`
        # extracted into dedicated fields.
        transforms.securix_parse = {
          type = "remap";
          inputs = [ "securix_journal" ]
            ++ lib.optional cfg.sources.auditFile.enable "securix_audit_file";
          source = ''
            parsed, err = parse_json(.message)
            if err == null && is_object(parsed) {
              . = merge(., object!(parsed))
            }
            if .source_type == "file" {
              .source_type = "auditd"
              .SYSLOG_IDENTIFIER = "auditd"
              ._SYSTEMD_UNIT = "auditd.service"
              m, me = parse_regex(.message, r'type=(?P<audit_type>[A-Z_]+)\s+msg=audit\((?P<audit_ts>\d+\.\d+):(?P<audit_seq>\d+)\)')
              if me == null {
                . = merge(., m)
              }
              k, ke = parse_regex(.message, r'key="(?P<audit_key>[^"]+)"')
              if ke == null {
                . = merge(., k)
              }
            }
          '';
        };
      } { transforms = filterTransforms; })
      (lib.recursiveUpdate os.extraSettings sl.extraSettings);

      # --------- OpenSearch sink ---------
      withOpenSearch = c:
        if !os.enable then c
        else lib.recursiveUpdate c {
          sinks.opensearch_logs = {
            type = "elasticsearch";
            inputs = [ filterChain ];
            endpoints = [ os.endpoint ];
            # OpenSearch 2.x (like Elasticsearch ≥ 8) removed the
            # `_type` metadata field from the bulk API. Force the v8
            # format so Vector omits it; the default "auto" picks v7
            # against OpenSearch and every document gets a 400.
            api_version = "v8";
            mode = "bulk";
            bulk.index = os.index;
            healthcheck.enabled = false;
          } // optionalAttrs hasOSAuth {
            auth = {
              strategy = "basic";
              user = os.auth.user;
              password = "\${SECURIX_OS_PASSWORD}";
            };
          } // optionalAttrs (os.tls.caFile != null || !os.tls.verifyCertificate) {
            tls = { verify_certificate = os.tls.verifyCertificate; }
              // optionalAttrs (os.tls.caFile != null) {
                ca_file = toString os.tls.caFile;
              };
          };
        };

      # --------- Syslog sink ---------
      # VRL formatter rewriting `.message` to an RFC 5424 line:
      #   <PRI>1 TIMESTAMP HOSTNAME APP-NAME - - - JSON-BODY
      #
      # Severity is derived from either `.PRIORITY` (journald sets
      # this to the original syslog severity) or `.level` (common
      # in structured slog payloads). Falls back to INFO (6).
      syslogFormatVRL = ''
        sev = 6
        if exists(.PRIORITY) {
          p = to_int(.PRIORITY) ?? 6
          if p >= 0 && p <= 7 { sev = p }
        }
        if exists(.level) {
          lvl = to_string(.level) ?? "INFO"
          if lvl == "ERROR" { sev = 3 }
          if lvl == "WARN"  { sev = 4 }
          if lvl == "INFO"  { sev = 6 }
          if lvl == "DEBUG" { sev = 7 }
        }

        pri = ${toString (facilityCode sl.facility * 8)} + sev
        ts = format_timestamp!(now(), "%Y-%m-%dT%H:%M:%S%.6fZ")
        hn = to_string(.host) ?? "-"
        body = encode_json(.)
        .message = "<" + to_string(pri) + ">1 " + ts + " " + hn + " ${sl.appName} - - - " + body
      '';

      syslogSinkBase = {
        type = "socket";
        inputs = [ "securix_syslog_format" ];
        mode = if sl.mode == "udp" then "udp" else "tcp";
        address = sl.endpoint;
        encoding.codec = "text";
      } // optionalAttrs (sl.mode != "udp") {
        framing.method = sl.framing;
      } // optionalAttrs (sl.mode == "tcp+tls") {
        tls = {
          enabled = true;
          verify_certificate = sl.tls.verifyCertificate;
          verify_hostname = sl.tls.verifyHostname;
        } // optionalAttrs (sl.tls.caFile != null) {
          ca_file = toString sl.tls.caFile;
        } // optionalAttrs (sl.tls.certFile != null) {
          crt_file = toString sl.tls.certFile;
        } // optionalAttrs hasSlMtls {
          key_file = "${credDir}/syslog_key";
        } // optionalAttrs hasSlKeyPass {
          key_pass = "\${SECURIX_SL_KEY_PASS}";
        };
      };

      withSyslog = c:
        if !sl.enable then c
        else lib.recursiveUpdate c {
          transforms.securix_syslog_format = {
            type = "remap";
            inputs = [ filterChain ];
            source = syslogFormatVRL;
          };
          sinks.syslog_out = syslogSinkBase;
        };

      finalConfig = withSyslog (withOpenSearch baseConfig);

      configFile = pkgs.writeText "securix-vector.json"
        (builtins.toJSON finalConfig);

      prepScript = pkgs.writeShellScript "securix-vector-prep" (
        optionalString hasOSAuth ''
          SECURIX_OS_PASSWORD="$(cat "$CREDENTIALS_DIRECTORY/os_password")"
          export SECURIX_OS_PASSWORD
        '' +
        optionalString hasSlKeyPass ''
          SECURIX_SL_KEY_PASS="$(cat "$CREDENTIALS_DIRECTORY/syslog_key_pass")"
          export SECURIX_SL_KEY_PASS
        ''
      );
    in
    mkIf anyEnabled {
      # Loud warnings when the operator selects a cleartext syslog
      # transport or disables TLS verification. Security-relevant
      # logs crossing an untrusted network in plaintext defeats
      # the whole point of centralised logging.
      warnings =
        lib.optional (sl.enable && sl.mode != "tcp+tls")
          "securix.logShipper.sinks.syslog.mode = \"${sl.mode}\": logs travel UNENCRYPTED to ${sl.endpoint}. Use \"tcp+tls\" (RFC 5425, default port 6514) unless you really need legacy compatibility."
        ++ lib.optional (os.enable && !os.tls.verifyCertificate)
          "securix.logShipper.sinks.opensearch.tls.verifyCertificate = false: the TLS channel to ${os.endpoint} is established but the peer identity is NOT checked. Lab only."
        ++ lib.optional (sl.enable && sl.mode == "tcp+tls" && !sl.tls.verifyCertificate)
          "securix.logShipper.sinks.syslog.tls.verifyCertificate = false: TLS is enabled but the peer identity is NOT checked. Lab only.";

      systemd.services.securix-log-shipper = {
        description =
          "Vector log shipper: journald → " +
          (lib.concatStringsSep " + " (
            lib.optional os.enable "OpenSearch" ++
            lib.optional sl.enable "syslog (${sl.mode})"
          ));
        wantedBy = [ "multi-user.target" ];
        # If any sink path resolves inside the standalone OpenBao
        # prefetch output directory, wait for that service so the
        # file is guaranteed to exist before LoadCredential tries
        # to read it.
        after = [ "network-online.target" ]
          ++ lib.optional (config.securix.openbao.enable or false && anyOpenbaoSecret)
            "securix-openbao.service";
        wants = [ "network-online.target" ]
          ++ lib.optional (config.securix.openbao.enable or false && anyOpenbaoSecret)
            "securix-openbao.service";

        serviceConfig = {
          Type = "simple";
          ExecStart = "${cfg.package}/bin/vector --config ${configFile}";
          Restart = "on-failure";
          RestartSec = "5s";
          DynamicUser = true;
          StateDirectory = "vector";
          StateDirectoryMode = "0700";

          # journald read requires membership in the systemd-journal
          # group; everything else is reachable via the Vector
          # upstream binary alone.
          SupplementaryGroups = [ "systemd-journal" ];

          LoadCredential =
            lib.optional hasOSAuth "os_password:${toString os.auth.passwordFile}" ++
            lib.optional hasSlMtls "syslog_key:${toString sl.tls.keyFile}" ++
            lib.optional hasSlKeyPass "syslog_key_pass:${toString sl.tls.keyPassFile}";

          ExecStartPre = lib.optional (hasOSAuth || hasSlKeyPass) prepScript;

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
          MemoryDenyWriteExecute = false;
        };
      };
    };
}
