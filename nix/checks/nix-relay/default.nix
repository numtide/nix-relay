{
  pkgs,
  perSystem,
  ...
}:

let
  # Generate JWKS and JWT token from the test RSA keys
  testCredentials =
    pkgs.runCommand "nix-relay-test-credentials"
      {
        nativeBuildInputs = [
          (pkgs.python3.withPackages (ps: [
            ps.pyjwt
            ps.cryptography
          ]))
        ];
      }
      ''
        python3 ${./gen-test-credentials.py} \
          ${../../../testdata/test_key.pem} \
          ${../../../testdata/test_key.pub.pem} \
          "$out"
      '';

  nixRelayModule = ../../modules/nixos/nix-relay.nix;

  # Directory layout matching the OIDC URL paths so nginx can serve with root
  oidcRoot = pkgs.runCommand "mock-oidc-root" { } ''
    mkdir -p "$out/.well-known"
    cp ${testCredentials}/discovery.json "$out/.well-known/openid-configuration"
    cp ${testCredentials}/jwks.json "$out/jwks"
  '';

  tokenFile = "${testCredentials}/token";
in
pkgs.testers.nixosTest {
  name = "nix-relay";

  nodes.server = {
    imports = [ nixRelayModule ];
    _module.args.perSystem = perSystem;

    services.nix-relay = {
      enable = true;
      openFirewall = true;
      settings = {
        auth.issuer = "http://localhost:9999";
        auth.audience = "api://nix-relay";
        auth.allowed_org = "testorg";
        daemon.nix_daemon_path = "${pkgs.coreutils}/bin/cat";
        daemon.extra_args = [ ];
        server.listen = "0.0.0.0:8080";
      };
    };

    # Mock OIDC provider via nginx
    services.nginx = {
      enable = true;
      virtualHosts."localhost" = {
        listen = [
          {
            addr = "0.0.0.0";
            port = 9999;
          }
        ];
        root = oidcRoot;
        locations."/".extraConfig = ''
          default_type application/json;
        '';
      };
    };
    networking.firewall.allowedTCPPorts = [ 9999 ];
  };

  nodes.client =
    { pkgs, ... }:
    {
      environment.systemPackages = [
        pkgs.websocat
        pkgs.curl
      ];
    };

  testScript = ''
    start_all()

    # Wait for mock OIDC provider
    server.wait_for_unit("nginx")
    server.wait_for_open_port(9999)

    # Verify mock OIDC serves discovery and JWKS
    server.succeed(
        "curl -sf http://localhost:9999/.well-known/openid-configuration | grep jwks_uri"
    )
    server.succeed("curl -sf http://localhost:9999/jwks | grep test-kid")

    # Wait for nix-relay service
    server.wait_for_unit("nix-relay")
    server.wait_for_open_port(8080)

    # Read the pre-generated JWT token
    token = server.succeed("cat ${tokenFile}").strip()

    # Test: client connects with valid JWT, sends data, gets echo back
    # Note: websocat requires -H at the end or with = to avoid argument confusion
    result = client.succeed(
        f"printf 'hello nix-relay' | timeout 5 websocat --binary ws://server:8080/relay -H='Authorization: Bearer {token}'"
    ).strip()
    assert result == "hello nix-relay", f"expected echo, got: {result!r}"

    # Test: unauthenticated WebSocket connection is rejected
    client.fail(
        "echo test | timeout 5 websocat --binary ws://server:8080/relay"
    )
  '';
}
