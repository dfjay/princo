# The rule data of each preset princo.yaml's rule_data can name, as
# princo deploy downloads it (internal/fleet/ruledata.go): from nixpkgs, or
# pinned in rule-data.json where nixpkgs doesn't package it.
{ pkgs }:

let
  pins = builtins.fromJSON (builtins.readFile ./rule-data.json);
  pinned = preset: kind: pkgs.fetchurl { inherit (pins.${preset}.${kind}) url hash; };
in
{
  runetfreedom = {
    geoip = pinned "runetfreedom" "geoip";
    geosite = pinned "runetfreedom" "geosite";
  };
  loyalsoldier = {
    geoip = "${pkgs.v2ray-rules-dat}/share/v2ray/geoip.dat";
    geosite = "${pkgs.v2ray-rules-dat}/share/v2ray/geosite.dat";
  };
  v2fly = {
    geoip = "${pkgs.v2ray-geoip}/share/v2ray/geoip.dat";
    geosite = "${pkgs.v2ray-domain-list-community}/share/v2ray/geosite.dat";
  };
  dbip = {
    geoip = pkgs.dbip-country-lite.mmdb;
  };
}
