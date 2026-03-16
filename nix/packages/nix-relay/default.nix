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
      pkgs.darwin.apple_sdk.frameworks.Security
      pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
    ];
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;
  }
)
