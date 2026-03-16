{
  pkgs,
  inputs,
  ...
}:
let
  craneLib = inputs.crane.mkLib pkgs;

  src = pkgs.lib.cleanSourceWith {
    src = ../../..;
    filter =
      path: type:
      (craneLib.filterCargoSources path type) || (builtins.match ".*testdata/.*" path != null);
  };

  commonArgs = {
    inherit src;
    strictDeps = true;
    buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
      pkgs.libiconv
      pkgs.apple-sdk
    ];
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;
    meta.mainProgram = "nix-relay";
  }
)
