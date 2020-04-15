{ pkgs
}:

let
  nix-hs = import (builtins.fetchGit {
    url = "https://code.devalot.com/open/nix-hs.git";
    rev = "136d1a5c1e87c2ef5e8050c6b521f4d529645eba";
    ref = "next";
  }) { inherit pkgs; };

  license = ../LICENSE;

  with-patches = args:
    (nix-hs args).overrideAttrs (_orig: {
      # Replace symlinks that point outside of the project:
      postPatch = ''
        rm LICENSE
        cp ${license} LICENSE
      '';
    });

in with-patches
