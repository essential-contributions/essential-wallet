{
  description = ''
    A nix flake for the essential wallet.
  '';

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = inputs:
    let
      overlays = [
        inputs.self.overlays.default
      ];
      perSystemPkgs = f:
        inputs.nixpkgs.lib.genAttrs (import inputs.systems)
          (system: f (import inputs.nixpkgs { inherit overlays system; }));
    in
    {
      overlays = {
        essential-wallet = import ./overlay.nix { };
        default = inputs.self.overlays.essential-wallet;
      };

      packages = perSystemPkgs (pkgs: {
        essential-wallet = pkgs.essential-wallet;
        essential-wallet-test = pkgs.essential-wallet-test;
        default = inputs.self.packages.${pkgs.system}.essential-wallet;
      });

      devShells = perSystemPkgs (pkgs: {
        essential-wallet-dev = pkgs.callPackage ./shell.nix { };
        default = inputs.self.devShells.${pkgs.system}.essential-wallet-dev;
      });

      apps = perSystemPkgs (pkgs: {
        wallet = {
          type = "app";
          program = "${pkgs.essential-wallet}/bin/essential-wallet";
        };
        wallet-test = {
          type = "app";
          program = "${pkgs.essential-wallet-test}/bin/essential-wallet-test";
        };
        default = inputs.self.apps.${pkgs.system}.wallet;
      });

      formatter = perSystemPkgs (pkgs: pkgs.nixpkgs-fmt);
    };
}
