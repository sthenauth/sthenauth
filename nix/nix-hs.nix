{ sources ? import ./sources.nix, pkgs ? import sources.nixpkgs { } }:

let
  nix-hs = import sources.nix-hs { inherit pkgs; };

  license = ../LICENSE;
  changes = ../CHANGES.md;
  setup = ../Setup.hs;

  # Replace symlinks that point outside of the project:
  postPatch = ''
    rm LICENSE CHANGES.md Setup.hs
    cp ${license} LICENSE
    cp ${changes} CHANGES.md
    cp ${setup} Setup.hs
  '';

  with-patches = args:
    nix-hs (args // {
      postPatch = ''
        ${args.postPatch or ""}
        ${postPatch}
      '';
    });

in with-patches
