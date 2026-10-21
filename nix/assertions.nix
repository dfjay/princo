# Evaluates node de with an nginx virtual host on 443, as `forceSSL` without
# `listen` gives it, and with a sing-box older than its config needs, and
# checks the module refuses both.
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
          # Only its version is read.
          enginePackage = pkgs.sing-box.overrideAttrs {
            version = "1.14.0-rc.1";
            __intentionallyOverridingVersion = true;
          };
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
  expect =
    what:
    lib.assertMsg (lib.any (lib.hasInfix what) failed) "expected a failed assertion naming ${what}, got: ${builtins.toJSON failed}";
in
assert expect "blog.example.com";
assert expect "sing-box 1.14.0 or newer";
assert lib.assertMsg (
  lib.length failed == 2
) "expected two failed assertions, got: ${builtins.toJSON failed}";
pkgs.runCommand "princo-module-assertions" { } "touch $out"
