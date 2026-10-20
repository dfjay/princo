# Evaluates node de with an nginx virtual host on 443, as `forceSSL` without
# `listen` gives it, and checks the module refuses it.
{
  self,
  nixpkgs,
  pkgs,
}:

let
  inherit (pkgs) lib;
  node = nixpkgs.lib.nixosSystem {
    system = lib.replaceStrings [ "darwin" ] [ "linux" ] pkgs.stdenv.hostPlatform.system;
    modules = [
      self.nixosModules.default
      {
        services.princo = {
          enable = true;
          config = ../testdata/fleet/princo.yaml;
          node = "de";
          secretsDir = "/run/princo-secrets";
          planPkgs = pkgs;
        };
        services.nginx.virtualHosts."blog.example.com" = {
          forceSSL = true;
          enableACME = true;
        };
        boot.loader.grub.enable = false;
        fileSystems."/" = {
          device = "none";
          fsType = "tmpfs";
        };
        system.stateVersion = "26.05";
      }
    ];
  };
  failed = map (a: a.message) (lib.filter (a: !a.assertion) node.config.assertions);
in
assert lib.assertMsg (lib.any (lib.hasInfix "blog.example.com") failed)
  "expected the mux port assertion to name blog.example.com, got: ${builtins.toJSON failed}";
assert lib.assertMsg (lib.length failed == 1) "expected one failed assertion, got: ${builtins.toJSON failed}";
pkgs.runCommand "princo-module-assertions" { } "touch $out"
