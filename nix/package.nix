{
  lib,
  buildGoModule,
  go_1_27,
}:

(buildGoModule.override { go = go_1_27; }) {
  pname = "princo";
  version = "0-unstable";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
      ../testdata
    ];
  };

  vendorHash = "sha256-SByJU1Nf1P95ikwA0/95YrSCNRWXUez2CE3rBG+PfH4=";

  ldflags = [
    "-s"
    "-w"
  ];

  meta = {
    description = "Declarative VPN fleet: one princo.yaml renders sing-box configs for every node";
    homepage = "https://github.com/dfjay/princo";
    license = lib.licenses.mit;
    mainProgram = "princo";
  };
}
