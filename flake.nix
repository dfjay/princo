{
  description = "Declarative VPN fleet: one princo.yaml renders sing-box configs for every node";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        princo = pkgs.callPackage ./nix/package.nix { };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.princo;
      });

      overlays.default = final: _: { princo = final.callPackage ./nix/package.nix { }; };

      nixosModules.default = ./nix/module.nix;

      checks = forAllSystems (
        pkgs:
        {
          inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) princo;
        }
        // {
          # On darwin the VM runs natively and the Linux side builds on a remote or linux-builder machine.
          nixos = pkgs.testers.runNixOSTest (import ./nix/test.nix { inherit self; });
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
