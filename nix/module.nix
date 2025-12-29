{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.mdns-filter;

  # Convert Nix rules attrset to YAML-compatible structure
  rulesYaml = lib.mapAttrsToList (name: rule: {
    inherit name;
    inherit (rule) match action;
  } // lib.optionalAttrs (rule.matchMode != null) {
    match_mode = rule.matchMode;
  } // lib.optionalAttrs (rule.log != null) {
    inherit (rule) log;
  }) cfg.rules;

  # Generate the full config
  configYaml = {
    default_action = cfg.defaultAction;
    rules = rulesYaml;
  };

  configFile = if cfg.configFile != null
    then cfg.configFile
    else pkgs.writeText "mdns-filter.yaml" (lib.generators.toYAML {} configYaml);

  # Match criteria submodule
  matchModule = lib.types.submodule {
    options = {
      src_ip = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "192.168.1.0/24";
        description = "Source IP address in CIDR notation.";
      };

      is_query = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        description = "Match query packets (true) or response packets (false).";
      };

      service = lib.mkOption {
        type = lib.types.nullOr (lib.types.either lib.types.str (lib.types.listOf lib.types.str));
        default = null;
        example = "_googlecast._tcp";
        description = "Service type pattern(s) to match.";
      };

      instance = lib.mkOption {
        type = lib.types.nullOr (lib.types.either lib.types.str (lib.types.listOf lib.types.str));
        default = null;
        example = "Google-Cast-*";
        description = "Instance name pattern(s) to match.";
      };

      name = lib.mkOption {
        type = lib.types.nullOr (lib.types.either lib.types.str (lib.types.listOf lib.types.str));
        default = null;
        description = "Full DNS name pattern(s) to match.";
      };

      record_type = lib.mkOption {
        type = lib.types.nullOr (lib.types.either lib.types.str (lib.types.listOf lib.types.str));
        default = null;
        example = "PTR";
        description = "Record type(s) to match (A, AAAA, PTR, SRV, TXT, etc.).";
      };

      section = lib.mkOption {
        type = lib.types.nullOr (lib.types.either lib.types.str (lib.types.listOf lib.types.str));
        default = null;
        example = "answer";
        description = "Packet section(s) to match (question, answer, authority, additional).";
      };

      txt_contains = lib.mkOption {
        type = lib.types.nullOr (lib.types.either lib.types.str (lib.types.listOf lib.types.str));
        default = null;
        example = "md=*Bridge*";
        description = "TXT record content pattern(s) to match.";
      };
    };
  };

  # Filter out null values from match attrset
  cleanMatch = match: lib.filterAttrs (_: v: v != null) match;

  # Rule submodule
  ruleModule = lib.types.submodule {
    options = {
      match = lib.mkOption {
        type = matchModule;
        description = "Matching criteria for this rule.";
        apply = cleanMatch;
      };

      action = lib.mkOption {
        type = lib.types.enum [ "allow" "deny" ];
        description = "Action to take when rule matches.";
      };

      matchMode = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum [ "any" "all" ]);
        default = null;
        description = "How to match records: 'any' (default) or 'all'.";
      };

      log = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum [ "none" "debug" "info" ]);
        default = null;
        description = "Log level when rule matches.";
      };
    };
  };

in
{
  options.services.mdns-filter = {
    enable = lib.mkEnableOption "mdns-filter, a filtering mDNS repeater";

    package = lib.mkPackageOption pkgs "mdns-filter" { };

    interfaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      description = "Network interfaces to bridge (minimum 2 required).";
      example = [ "eth0" "wlan0" ];
    };

    defaultAction = lib.mkOption {
      type = lib.types.enum [ "allow" "deny" ];
      default = "allow";
      description = "Default action when no rules match.";
    };

    dryRun = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Log decisions without actually forwarding packets.";
    };

    rules = lib.mkOption {
      type = lib.types.attrsOf ruleModule;
      default = { };
      description = "Filter rules, evaluated in order. First match wins.";
      example = lib.literalExpression ''
        {
          deny-iot = {
            match = { src_ip = "192.168.10.0/24"; };
            action = "deny";
          };
          allow-cast = {
            match = { instance = "Google-Cast-*"; };
            action = "allow";
          };
        }
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to a YAML configuration file. If set, this takes precedence
        over the `rules` and `defaultAction` options.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.length cfg.interfaces >= 2;
        message = "services.mdns-filter.interfaces must have at least 2 interfaces.";
      }
    ];

    systemd.services.mdns-filter = {
      description = "mDNS Repeater";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = lib.concatStringsSep " " ([
          (lib.getExe cfg.package)
        ] ++ lib.optional cfg.dryRun "--dry-run"
          ++ [ "--filter-config" configFile ]
          ++ cfg.interfaces);

        # Security: run as a transient unprivileged user
        DynamicUser = true;

        # Grant only the capability needed for raw socket operations
        AmbientCapabilities = [ "CAP_NET_RAW" ];
        CapabilityBoundingSet = [ "CAP_NET_RAW" ];

        # Additional hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;

        # Restart on failure
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
