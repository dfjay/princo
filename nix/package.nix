{
  lib,
  buildGoModule,
  go_1_27,
  # The commit, for `princo version`; the flake passes its own.
  rev ? null,
}:

(buildGoModule.override { go = go_1_27; }) {
  pname = "princo";
  version =
    lib.trim (builtins.readFile ../internal/version/VERSION)
    + lib.optionalString (rev != null) "+${rev}";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
      ../testdata
      ../examples
    ];
  };

  # Repository tooling, not part of princo.
  excludedPackages = [ "internal/tools" ];

  vendorHash = "sha256-MpU7Od7xVa3+38+jP0ybPI4moZ2Ez+x8A/3VkIKwHys=";

  ldflags = [
    "-s"
    "-w"
  ]
  ++ lib.optionals (rev != null) [
    "-X github.com/dfjay/princo/internal/version.Revision=${rev}"
  ];

  meta = {
    description = "Declarative VPN fleet: one princo.yaml renders the configs of every node";
    homepage = "https://github.com/dfjay/princo";
    license = lib.licenses.mit;
    mainProgram = "princo";
  };
}
