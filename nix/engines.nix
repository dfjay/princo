# What the NixOS module needs to know about each engine princo renders
# for. Adding an engine is adding an entry here.
{ lib, pkgs }:

{
  sing-box = {
    package = pkgs.sing-box;
    # The command line that runs the engine on the rendered config.
    command =
      {
        package,
        config,
        stateDir,
      }:
      [
        (lib.getExe package)
        "-D"
        stateDir
        "-c"
        config
        "run"
      ];
    # Whether SIGHUP reloads the config.
    reloads = true;
    # Where a file of plan.rule_sets comes from.
    ruleSet =
      file:
      let
        source = if lib.hasPrefix "geoip-" file then pkgs.sing-geoip else pkgs.sing-geosite;
      in
      "${source}/share/sing-box/rule-set/${file}";
  };
}
