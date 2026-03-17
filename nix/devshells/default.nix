{
  pkgs,
  inputs,
  perSystem,
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
    perSystem.self.formatter
    pkgs.rust-analyzer
    pkgs.cargo
    pkgs.rustc
  ];
}
