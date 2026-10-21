{
  description = "Declarative VPN fleet: one princo.yaml renders the configs of every node";

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
      # The package, with the commit it's built from in `princo version`.
      princo =
        pkgs: pkgs.callPackage ./nix/package.nix { rev = self.shortRev or self.dirtyShortRev or null; };
    in
    {
      packages = forAllSystems (pkgs: {
        princo = princo pkgs;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.princo;
      });

      # Tools for working on princo: `nix develop`, or direnv with .envrc.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go_1_27
            golangci-lint
            goreleaser
            syft
            just
            nix-update
            nixfmt
            sing-box # the tests run `sing-box check` on rendered configs
            xray # and `xray run -test`
            age
            sops
          ];
        };
      });

      overlays.default = final: _: { princo = princo final; };

      nixosModules.default =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.princo.package = lib.mkDefault (princo pkgs);
        };

      checks = forAllSystems (
        pkgs:
        {
          inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) princo;
        }
        // {
          # On darwin the VM runs natively and the Linux side builds on a remote or linux-builder machine.
          nixos = pkgs.testers.runNixOSTest (import ./nix/test.nix { inherit self; });
          assertions = import ./nix/assertions.nix { inherit self nixpkgs pkgs; };
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
