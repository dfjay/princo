# Evaluates testdata/split and checks each sops secret is read from beside
# the config file that maps it.
{
  self,
  nixpkgs,
  pkgs,
}:

let
  inherit (pkgs) lib;
  private = "${../testdata/split}/private repo";
  node = nixpkgs.lib.nixosSystem {
    system = lib.replaceStrings [ "darwin" ] [ "linux" ] pkgs.stdenv.hostPlatform.system;
    modules = [
      self.nixosModules.default
      # Stands in for sops-nix: only the option the module sets.
      {
        options.sops.secrets = lib.mkOption {
          type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
          default = { };
        };
      }
      {
        services.princo = {
          enable = true;
          config = [
            ../testdata/split/public/princo.yaml
            # As a flake input gives it, with a space to quote.
            "${private}/princo.yaml"
          ];
          node = "fr";
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
  secrets = lib.mapAttrs (_: s: toString s.sopsFile) node.config.sops.secrets;
  want = {
    "princo/nodes/fr/reality" = "${private}/secrets/fr.yaml";
    "princo/users/alice" = toString ../testdata/split/secrets/shared.yaml;
  };
  render = node.config.systemd.services.princo-render.serviceConfig.ExecStart;
in
assert lib.assertMsg (
  secrets == want
) "sops files: want ${builtins.toJSON want}, got ${builtins.toJSON secrets}";
assert lib.assertMsg (
  lib.length (lib.filter (lib.hasInfix "--config") (lib.splitString " " render)) == 2
  && lib.hasInfix "'" render
) "princo-render should get both config files: ${render}";
pkgs.runCommand "princo-module-several-files" { } "touch $out"
