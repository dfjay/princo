# Runs one node of a princo fleet on NixOS.
#
# At build time `princo plan` says what the node needs around its files:
# ports, the SNI multiplexer, certificates, rule sets and secrets. The module
# turns that into firewall rules, an nginx stream map, ACME certificates and
# sops-nix secrets. On the host, princo-render.service renders the node's
# files from the decrypted secrets, and princo.service runs the node's engine
# (engines.nix) on them; no secret reaches the Nix store.
{
  config,
  lib,
  pkgs,
  options,
  ...
}:

let
  cfg = config.services.princo;

  # The plan is read at evaluation, so princo runs where the system is
  # evaluated, not where it runs.
  planPrinco =
    if cfg.planPkgs.stdenv.hostPlatform.system == pkgs.stdenv.hostPlatform.system then
      cfg.package
    else
      cfg.planPkgs.callPackage ./package.nix { };
  plan = lib.importJSON (
    cfg.planPkgs.runCommand "princo-plan-${cfg.node}" { } ''
      ${lib.getExe planPrinco} --config ${cfg.config} plan --node ${lib.escapeShellArg cfg.node} > $out
    ''
  );

  engines = import ./engines.nix {
    inherit lib;
    pkgs = cfg.enginePkgs;
  };
  engine =
    engines.${plan.engine}
      or (throw "services.princo: node ${cfg.node} uses engine ${plan.engine}, which the module can't run yet (nix/engines.nix).");

  # Where princo-render writes the node's files.
  outDir = "/run/princo/files";
  # Absent from the plan JSON when the node has none.
  site = plan.subscription or null;
  mux = plan.mux or null;
  siteRoot = "${outDir}/${site.root}";

  useSops = cfg.secretsDir == null;
  secretsDir = if useSops then "/run/secrets/princo" else cfg.secretsDir;
  sopsFormat =
    file:
    if lib.hasSuffix ".json" file then
      "json"
    else if lib.hasSuffix ".env" file then
      "dotenv"
    else if lib.hasSuffix ".ini" file then
      "ini"
    else
      "yaml";
  notSops = lib.filter (s: s.source.type != "sops") plan.secrets;

  ruleSetDir = pkgs.linkFarm "princo-rule-sets" (
    map (file: {
      name = file;
      path = engine.ruleSet file;
    }) plan.rule_sets
  );
  certUnits = map (d: "acme-${d}.service") plan.certificates;
  # The certificates the engine reads, not nginx.
  engineDomains = lib.filter (d: site == null || d != site.domain) plan.certificates;
  acmeWebroot = "/var/lib/acme/acme-challenge";

  needsNginx = mux != null || plan.certificates != [ ];
  http = [
    {
      addr = "0.0.0.0";
      port = 80;
    }
    {
      addr = "[::]";
      port = 80;
    }
  ];
  # The TCP ports an nginx virtual host listens on, the way the nginx module
  # works them out.
  vhostPorts =
    vhost:
    let
      nginx = config.services.nginx;
      hasSSL = vhost.onlySSL || vhost.addSSL || vhost.forceSSL;
      orDefault = v: d: if v == null then d else v;
      tcp = lines: lib.filter (l: !lib.hasPrefix "unix:" (l.addr or "")) lines;
      defaultPorts =
        line:
        lib.optional ((hasSSL || vhost.rejectSSL) && orDefault (line.ssl or null) true) (
          orDefault (line.port or null) nginx.defaultSSLListenPort
        )
        ++ lib.optional (!vhost.onlySSL && !(orDefault (line.ssl or null) false)) (
          orDefault (line.port or null) nginx.defaultHTTPListenPort
        );
    in
    if vhost.listen != [ ] then
      map (l: orDefault l.port 80) (tcp vhost.listen)
    else
      lib.concatMap defaultPorts (
        if nginx.defaultListen != [ ] then tcp nginx.defaultListen else [ { } ]
      );
  # Other virtual hosts on the multiplexer's port would take it from it.
  muxConflicts = lib.optionals (mux != null) (
    lib.attrNames (
      lib.filterAttrs (_: v: lib.elem mux.port (vhostPorts v)) config.services.nginx.virtualHosts
    )
  );

  # Nix orders 1.14.0-rc.1 after 1.14.0; the engines, before it.
  engineNewEnough =
    let
      v = cfg.enginePackage.version;
      release = lib.head (lib.splitString "-" v);
    in
    if release == v then
      lib.versionAtLeast v plan.engine_min_version
    else
      lib.versionOlder plan.engine_min_version release;

  parseAddr =
    addr:
    let
      m = builtins.match "(.*):([0-9]+)" addr;
    in
    {
      addr = builtins.elemAt m 0;
      port = lib.toInt (builtins.elemAt m 1);
    };
in
{
  options.services.princo = {
    enable = lib.mkEnableOption "a node of a princo VPN fleet";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "princo built with the host's nixpkgs";
      description = "The princo package.";
    };

    config = lib.mkOption {
      type = lib.types.path;
      example = lib.literalExpression "./vpn/princo.yaml";
      description = ''
        The fleet's princo.yaml. Secret files it names are relative to its
        directory, so pass it as a Nix path, not a string.
      '';
    };

    node = lib.mkOption {
      type = lib.types.str;
      example = "fr";
      description = "The node of the fleet this host runs.";
    };

    secretsDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/agenix/princo";
      description = ''
        Directory holding the node's secrets, one file per secret path
        (users/alice, nodes/fr/reality, ...). When null, the module has
        sops-nix decrypt them from the sops files princo.yaml's `secrets:`
        block names, which needs sops-nix imported.
      '';
    };

    enginePkgs = lib.mkOption {
      type = lib.types.pkgs;
      default = pkgs;
      defaultText = lib.literalExpression "princo's nixpkgs input with its flake, else pkgs";
      example = lib.literalExpression "inputs.nixpkgs-unstable.legacyPackages.x86_64-linux";
      description = ''
        The nixpkgs the engine and its rule sets come from. princo's flake
        sets its own nixpkgs input, nixos-unstable, which follows engine
        releases more closely than a stable channel.
      '';
    };

    enginePackage = lib.mkOption {
      type = lib.types.package;
      default = engine.package;
      defaultText = lib.literalExpression "the package of the node's engine from enginePkgs, e.g. enginePkgs.sing-box";
      description = "The package of the engine the node runs.";
    };

    planPkgs = lib.mkOption {
      type = lib.types.pkgs;
      default = pkgs;
      defaultText = lib.literalExpression "pkgs";
      example = lib.literalExpression "inputs.nixpkgs.legacyPackages.aarch64-darwin";
      description = ''
        The nixpkgs `princo plan` runs with while the system is evaluated
        (import from derivation). By default that's the host's, which needs
        a builder for the host's platform even just to evaluate; set it to
        the packages of the machine you deploy from to plan there.
      '';
    };

    plan = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      description = "The node's plan from `princo plan`, for inspection.";
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        services.princo.plan = plan;

        assertions = [
          {
            assertion = muxConflicts == [ ];
            message = ''
              services.princo: these nginx virtual hosts listen on port ${toString mux.port}, which node ${cfg.node}'s multiplexer owns:
                ${lib.concatStringsSep "\n  " muxConflicts}
              Have them listen on 127.0.0.1:8443 and route their domains there with `passthrough:` in princo.yaml.
            '';
          }
          {
            assertion = engineNewEnough;
            message = "services.princo: node ${cfg.node}'s config needs ${plan.engine} ${plan.engine_min_version} or newer; services.princo.enginePackage is ${cfg.enginePackage.version}.";
          }
          {
            assertion = !useSops || options ? sops;
            message = "services.princo: import sops-nix, or set services.princo.secretsDir.";
          }
          {
            assertion = !useSops || notSops == [ ];
            message = ''
              services.princo: these secrets of node ${cfg.node} aren't in sops files, so sops-nix can't provide them:
                ${lib.concatMapStringsSep "\n  " (s: "${s.path} (${s.source.type}:${s.source.file})") notSops}
              Map them to sops files in princo.yaml's secrets: block, or set services.princo.secretsDir.
            '';
          }
        ];

        # May read the engine's config and certificates.
        users.groups.princo-engine = { };

        networking.firewall = {
          allowedTCPPorts = plan.tcp_ports ++ lib.optional (plan.certificates != [ ]) 80;
          allowedUDPPorts = plan.udp_ports;
        };

        # The paths the rendered config refers to.
        systemd.tmpfiles.rules = [
          "d /var/lib/princo 0755 root root -"
          "L+ /var/lib/princo/rules - - - - ${ruleSetDir}"
          "L+ /var/lib/princo/certs - - - - /var/lib/acme"
        ];

        systemd.services.princo-render = {
          description = "Render princo files of node ${cfg.node}";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            RuntimeDirectory = "princo";
            RuntimeDirectoryPreserve = true;
            UMask = "0027";
            ExecStart = lib.escapeShellArgs [
              (lib.getExe cfg.package)
              "--config"
              "${cfg.config}"
              "--secrets-dir"
              secretsDir
              "render"
              "--node"
              cfg.node
              "--out"
              outDir
            ];
            # The engine reads its config, nginx serves the subscription
            # site; the rest stays root's.
            ExecStartPost = [
              "${pkgs.coreutils}/bin/chgrp princo-engine ${outDir} ${outDir}/${plan.config}"
            ]
            ++ lib.optionals (site != null) [
              "${pkgs.coreutils}/bin/chmod 0751 ${outDir}"
              "${pkgs.coreutils}/bin/chgrp -R ${config.services.nginx.group} ${siteRoot}"
            ];
          };
        };

        systemd.services.princo =
          let
            caps = [
              "CAP_NET_ADMIN"
              "CAP_NET_BIND_SERVICE"
              "CAP_NET_RAW"
            ];
          in
          {
            description = "princo node ${cfg.node} (${plan.engine})";
            wantedBy = [ "multi-user.target" ];
            requires = [ "princo-render.service" ];
            # Restarts with princo-render, so new files take effect.
            partOf = [ "princo-render.service" ];
            wants = [ "network-online.target" ] ++ certUnits;
            after = [
              "network-online.target"
              "princo-render.service"
            ]
            ++ certUnits;
            inherit (engine) environment;
            serviceConfig = {
              ExecStart = lib.escapeShellArgs (
                engine.command {
                  package = cfg.enginePackage;
                  config = "${outDir}/${plan.config}";
                  stateDir = "/var/lib/princo-${plan.engine}";
                }
              );
              ExecReload = lib.mkIf engine.reloads "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
              DynamicUser = true;
              SupplementaryGroups = [ "princo-engine" ];
              StateDirectory = "princo-${plan.engine}";
              StateDirectoryMode = "0700";
              AmbientCapabilities = caps;
              CapabilityBoundingSet = caps;
              Restart = "on-failure";
              RestartSec = "10s";
              RestartPreventExitStatus = lib.mkIf (engine ? configError) engine.configError;
              LimitNOFILE = "infinity";
              ProtectClock = true;
              ProtectControlGroups = true;
              ProtectHostname = true;
              ProtectKernelLogs = true;
              ProtectKernelModules = true;
              ProtectKernelTunables = true;
              LockPersonality = true;
              RestrictNamespaces = true;
              RestrictRealtime = true;
              RestrictAddressFamilies = [
                "AF_INET"
                "AF_INET6"
                "AF_NETLINK"
                "AF_UNIX"
              ];
              SystemCallArchitectures = "native";
            };
          };

        security.acme = lib.mkIf (plan.certificates != [ ]) {
          acceptTerms = true;
          defaults.email = lib.mkIf (plan.acme_email or "" != "") (lib.mkDefault plan.acme_email);
          certs = lib.genAttrs engineDomains (_: {
            webroot = acmeWebroot;
            group = "princo-engine";
            reloadServices = [ "princo.service" ];
          });
        };

        services.nginx = lib.mkIf needsNginx {
          enable = true;
          streamConfig = lib.mkIf (mux != null) ''
            map $ssl_preread_server_name $princo_backend {
              ${lib.concatMapStringsSep "\n  " (r: "${r.sni} ${r.target};") mux.routes}
              ${lib.optionalString (mux.default or "" != "") "default ${mux.default};"}
            }
            server {
              listen ${toString mux.port};
              listen [::]:${toString mux.port};
              ssl_preread on;
              proxy_pass $princo_backend;
            }
          '';

          # The engine's domains: plain HTTP, only for ACME challenges.
          virtualHosts =
            lib.genAttrs engineDomains (_: {
              listen = lib.mkDefault http;
              locations."^~ /.well-known/acme-challenge/".root = acmeWebroot;
              locations."/".return = lib.mkDefault "404";
            })
            // lib.optionalAttrs (site != null) {
              ${site.domain} = {
                onlySSL = true;
                enableACME = true;
                listen = [ ((parseAddr site.listen) // { ssl = true; }) ];
                root = siteRoot;
                # Subscription URLs grant access: no log records their requests.
                extraConfig = ''
                  access_log off;
                  log_not_found off;
                  add_header X-Robots-Tag "noindex, nofollow" always;
                '';
                locations."~ ^/([a-f0-9]+)/sing-box$".extraConfig = ''
                  default_type application/json;
                  try_files /$1/sing-box/config =404;
                '';
                locations."~ ^/([a-f0-9]+)/qr$".extraConfig = ''
                  default_type text/html;
                  try_files /$1/index.html =404;
                '';
                # Named capture: the `if` regex below would reset $1.
                locations."~ ^/(?<token>[a-f0-9]+)/?$".extraConfig = ''
                  # sing-box apps send "SFx (sing-box ...)": give them the
                  # profile so the universal link works there too.
                  if ($http_user_agent ~ "^SF[A-Z] \(sing-box") {
                    rewrite ^ /$token/sing-box last;
                  }
                  default_type text/plain;
                  # add_header here drops the server's.
                  add_header X-Robots-Tag "noindex, nofollow" always;
                  add_header profile-update-interval "24";
                  add_header profile-title "${site.domain}";
                  add_header profile-web-page-url "https://${site.domain}/$token/qr";
                  try_files /$token/base64 =404;
                '';
              };
              # Its plain HTTP side, which forceSSL would generate with logging on.
              "${site.domain}-http" = {
                serverName = site.domain;
                listen = http;
                locations."^~ /.well-known/acme-challenge/".root = acmeWebroot;
                locations."/".return = "301 https://$host$request_uri";
                extraConfig = ''
                  access_log off;
                  log_not_found off;
                '';
              };
            };
        };
        # nginx reads the site that princo-render writes.
        systemd.services.nginx = lib.mkIf (site != null) {
          wants = [ "princo-render.service" ];
          after = [ "princo-render.service" ];
        };
      }

      {
        # nginx serves the challenges of the engine's certificates.
        systemd.services = lib.genAttrs (map (d: "acme-order-renew-${d}") engineDomains) (_: {
          wants = [ "nginx.service" ];
          after = [ "nginx.service" ];
        });
      }

      (lib.optionalAttrs (options ? sops) {
        sops.secrets = lib.mkIf useSops (
          lib.listToAttrs (
            map (s: {
              name = "princo/${s.file}";
              value = {
                sopsFile = dirOf cfg.config + "/${s.source.file}";
                format = sopsFormat s.source.file;
                key = s.source.key;
                restartUnits = [ "princo-render.service" ];
              };
            }) (lib.filter (s: s.source.type == "sops") plan.secrets)
          )
        );
      })
    ]
  );
}
