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
  };
}
