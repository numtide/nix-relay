{
  pkgs,
  flake,
  inputs,
  ...
}:
let
  mod = inputs.treefmt-nix.lib.evalModule pkgs {
    projectRootFile = ".git/config";

    programs = {
      nixfmt.enable = true;
      deadnix.enable = true;
      statix.enable = true;
      rustfmt.enable = true;
    };

    settings.formatter = {
      deadnix.priority = 1;
      statix.priority = 2;
      nixfmt.priority = 3;
    };
  };

  wrapper = mod.config.build.wrapper // {
    passthru.tests.check = mod.config.build.check flake;
  };
in
wrapper
