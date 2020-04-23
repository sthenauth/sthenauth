{ pkgs
}:

let
  nix-hs = import (builtins.fetchGit {
    url = "https://code.devalot.com/open/nix-hs.git";
    rev = "aae1474c1f90c891fa4aef0b43782046fb13339d";
    ref = "next";
  }) { inherit pkgs; };

  license = ../LICENSE;
  changes = ../CHANGES.md;
  setup   = ../Setup.hs;

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
