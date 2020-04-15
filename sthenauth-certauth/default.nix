{ pkgs ? import ../nix/nixpkgs.nix { }
}:

pkgs.nix-hs {
  cabal = ./sthenauth-certauth.cabal;
  overrides = import ../nix/overrides.nix pkgs;
}
