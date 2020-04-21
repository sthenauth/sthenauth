{ pkgs
}:

let
  nix-hs = import (builtins.fetchGit {
    url = "https://code.devalot.com/open/nix-hs.git";
    rev = "ab8f15a5a84d0d685c42e8fcfec3cf34755b562f";
    ref = "next";
  }) { inherit pkgs; };

  license = ../LICENSE;

  # Replace symlinks that point outside of the project:
  postPatch = ''
    rm LICENSE
    cp ${license} LICENSE
  '';

  with-patches = args:
    nix-hs (args // {
      postPatch = ''
        ${args.postPatch or ""}
        ${postPatch}
      '';
    });

in with-patches
