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
    # The engine's environment.
    environment = { };
    # Where a file of plan.rule_sets comes from.
    ruleSet =
      file:
      let
        source = if lib.hasPrefix "geoip-" file then pkgs.sing-geoip else pkgs.sing-geosite;
      in
      "${source}/share/sing-box/rule-set/${file}";
  };

  xray = {
    package = pkgs.xray;
    command =
      { package, config, ... }:
      [
        (lib.getExe package)
        "run"
        "-c"
        config
      ];
    reloads = false;
    # The exit status of a config it refuses, which restarting won't fix.
    configError = 23;
    # geoip.dat and geosite.dat, from the rule set dir.
    environment.XRAY_LOCATION_ASSET = "/var/lib/princo/rules";
    # Loyalsoldier's, as princo deploy downloads.
    ruleSet = file: "${pkgs.v2ray-rules-dat}/share/v2ray/${file}";
  };
}
