# Runs node de of the fixture fleet, which has everything: all three
# protocols, the multiplexer with a passthrough site, and the subscription
# site. Certificates are ACME's self-signed stand-ins. Beside it, node fi
# runs xray with XHTTP behind Reality.
{ self }:
{ pkgs, ... }:

let
  # The fixture's plaintext secrets, one file per path, as a secrets dir.
  secretsDir =
    pkgs.runCommand "princo-test-secrets"
      {
        nativeBuildInputs = [
          pkgs.yq-go
          pkgs.jq
        ];
      }
      ''
        yq -o=json ${../testdata/fleet/secrets.test.yaml} > secrets.json
        jq -r 'paths(scalars) | join("/")' secrets.json | while read -r path; do
          mkdir -p "$out/$(dirname "$path")"
          jq -j --arg p "$path" 'getpath($p | split("/"))' secrets.json > "$out/$path"
        done
      '';
in
{
  name = "princo";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.default ];
      services.princo = {
        enable = true;
        config = ../testdata/fleet/princo.yaml;
        node = "de";
        secretsDir = "${secretsDir}";
      };
      # Keep the stand-ins: never ask a real CA.
      security.acme.defaults.server = "https://127.0.0.1:1/directory";
      environment.systemPackages = [
        pkgs.curl
        pkgs.sing-box
      ];
    };

  nodes.fi =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.default ];
      services.princo = {
        enable = true;
        config = ../testdata/fleet/princo.yaml;
        node = "fi";
        secretsDir = "${secretsDir}";
      };
      environment.systemPackages = [ pkgs.xray ];
    };

  testScript = ''
    fi.wait_for_unit("princo.service")
    fi.wait_for_open_port(443)
    fi.succeed("grep -q '@princo-xhttp' /proc/net/unix")  # the XHTTP fallback
    fi.succeed("XRAY_LOCATION_ASSET=/var/lib/princo/rules xray run -test -c /run/princo/files/xray.json")

    machine.wait_for_unit("princo-render.service")
    machine.wait_for_unit("princo.service")
    machine.wait_for_unit("nginx.service")

    machine.succeed("sing-box check -c /run/princo/files/sing-box.json")
    machine.wait_for_open_port(443)   # nginx stream
    machine.wait_for_open_port(8444)  # vless-reality behind it
    machine.wait_for_open_port(8445)  # naive behind it
    machine.succeed("ss -Hlun 'sport = :443' | grep -q .")  # hysteria2

    # Through the multiplexer to the subscription site.
    token = machine.succeed("awk '$1 == \"alice\" {print $2}' /run/princo/files/tokens.txt").strip()
    curl = "curl -sfk --resolve subs.example.com:443:127.0.0.1 https://subs.example.com/" + token
    links = machine.succeed(curl + "/ | base64 -d")
    assert "#alice-de-reality" in links, links
    profile = machine.succeed(curl + "/ -A 'SFA (sing-box 1.14)'")
    assert '"outbounds"' in profile, profile
    assert "qr-sub.svg" in machine.succeed(curl + "/qr")
    assert "<svg" in machine.succeed(curl + "/qr-sub.svg")
    machine.fail("curl -sfk --resolve subs.example.com:443:127.0.0.1 https://subs.example.com/tokens.txt")

    closure = machine.succeed("nix-store -qR /run/current-system | grep -v princo-test-secrets").split()
    assert len(closure) > 100, closure
    machine.fail("grep -rlF wGTHAZhzR " + " ".join(closure))
  '';
}
