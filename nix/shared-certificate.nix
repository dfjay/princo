# Evaluates node de with a subscription domain under a certificate its
# engine serves too, and checks both read it and load it anew.
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
          config = [
            ../testdata/fleet/princo.yaml
            ../testdata/shared/princo.yaml
          ];
          node = "de";
          secretsDir = "/run/princo-secrets";
          planPkgs = pkgs;
        };
        security.acme.acceptTerms = true;
        boot.loader.grub.enable = false;
        fileSystems."/" = {
          device = "none";
          fsType = "tmpfs";
        };
        system.stateVersion = "26.05";
      }
    ];
  };
  inherit (node) config;
  failed = map (a: a.message) (lib.filter (a: !a.assertion) config.assertions);
  # nginx adds itself for its virtual hosts' certificates.
  certs = lib.mapAttrs (_: c: {
    inherit (c) group;
    reloadServices = lib.unique c.reloadServices;
  }) config.security.acme.certs;
  want = {
    "de.example.com" = {
      group = "princo-certs";
      reloadServices = [
        "nginx.service"
        "princo.service"
      ];
    };
    "naive-de.example.com" = {
      group = "princo-engine";
      reloadServices = [ "princo.service" ];
    };
    "subs.example.org" = {
      group = config.services.nginx.group;
      reloadServices = [ "nginx.service" ];
    };
  };
  groups = unit: config.systemd.services.${unit}.serviceConfig.SupplementaryGroups;
in
assert lib.assertMsg (failed == [ ]) "failed assertions: ${builtins.toJSON failed}";
assert lib.assertMsg (
  certs == want
) "certificates: want ${builtins.toJSON want}, got ${builtins.toJSON certs}";
assert lib.assertMsg (lib.elem "princo-certs" (groups "princo")) "the engine isn't in princo-certs";
assert lib.assertMsg (lib.elem "princo-certs" (groups "nginx")) "nginx isn't in princo-certs";
# de.example.com's challenges are the site's to answer.
assert lib.assertMsg (
  !(config.services.nginx.virtualHosts."de.example.com".locations ? "^~ /.well-known/acme-challenge/")
  && config.services.nginx.virtualHosts."de.example.com".useACMEHost == "de.example.com"
) "de.example.com should be the site's virtual host";
pkgs.runCommand "princo-module-shared-certificate" { } "touch $out"
