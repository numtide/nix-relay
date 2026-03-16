# Shell client that bridges stdin/stdout to the nix-relay WebSocket server.
# Used as remote-program in ssh-ng://localhost?remote-program=nix-relay-client
#
# TODO: wss:// could be added as a native transport in Nix, removing the need
# for this wrapper script and its curl/jq/websocat dependencies.
{
  pkgs,
  ...
}:
pkgs.resholve.mkDerivation {
  pname = "nix-relay-client";
  version = "0.1.0";
  src = ../../..;

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    install -Dm 755 client/nix-relay-client $out/bin/nix-relay-client
  '';

  solutions.default = {
    scripts = [ "bin/nix-relay-client" ];
    interpreter = "${pkgs.bash}/bin/bash";
    inputs = [
      pkgs.curl
      pkgs.jq
      pkgs.websocat
    ];
    execer = [ "cannot:${pkgs.websocat}/bin/websocat" ];
  };
}
