{
  description = "OIDC-authenticated Nix remote build relay";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-unstable";
    blueprint.url = "github:numtide/blueprint";
    blueprint.inputs.nixpkgs.follows = "nixpkgs";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    inputs:
    inputs.blueprint {
      inherit inputs;
      prefix = "nix";
    };
}
