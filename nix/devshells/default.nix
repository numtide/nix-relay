{
  pkgs,
  inputs,
  ...
}:
let
  craneLib = inputs.crane.mkLib pkgs;
in
craneLib.devShell {
  packages = [
    pkgs.websocat
    pkgs.jq
    pkgs.shellcheck
  ];
}
