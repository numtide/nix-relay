{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nix-relay;

  configFormat = pkgs.formats.toml { };
  configFile = configFormat.generate "nix-relay.toml" cfg.settings;
in
{
  options.services.nix-relay = {
    enable = lib.mkEnableOption "nix-relay OIDC-authenticated Nix remote build relay";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The nix-relay package to use.";
    };

    settings = lib.mkOption {
      default = { };
      type = configFormat.type;
      description = ''
        Configuration for nix-relay, serialized to TOML.
        See config.example.toml for available options.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open the listen port in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    # Sensible defaults matching config.rs
    services.nix-relay.settings = {
      server.listen = lib.mkDefault "0.0.0.0:8080";
      server.shutdown_grace_secs = lib.mkDefault 30;
      auth.issuer = lib.mkDefault "https://token.actions.githubusercontent.com";
      auth.audience = lib.mkDefault "api://nix-relay";
      auth.jwks_cache_ttl_secs = lib.mkDefault 3600;
      daemon.nix_daemon_path = lib.mkDefault "${config.nix.package}/bin/nix-daemon";
      daemon.extra_args = lib.mkDefault [ "--stdio" ];
      daemon.timeout_secs = lib.mkDefault 3600;
      daemon.max_connections = lib.mkDefault 32;
    };

    users.users.nix-relay = {
      description = "nix-relay service user";
      isSystemUser = true;
      group = "nix-relay";
    };

    users.groups.nix-relay = { };

    networking.firewall.allowedTCPPorts =
      let
        # Parse "host:port" to extract port number
        listenAddr = cfg.settings.server.listen or "0.0.0.0:8080";
        port = lib.toInt (lib.last (lib.splitString ":" listenAddr));
      in
      lib.mkIf cfg.openFirewall [ port ];

    systemd.services.nix-relay = {
      description = "nix-relay OIDC-authenticated Nix remote build relay";
      path = [
        cfg.package
        config.nix.package
      ];
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      serviceConfig = {
        User = "nix-relay";
        Restart = "always";
        ExecStart = "${lib.getExe cfg.package} ${configFile}";

        # Hardening
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        RestrictNamespaces = true;
      };
    };
  };
}
