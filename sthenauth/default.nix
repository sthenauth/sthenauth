{ pkgs ? import ../nix/nixpkgs.nix { }
}:

pkgs.nix-hs {
  cabal = ./sthenauth.cabal;
  overrides = import ../nix/overrides-sans-sthenauth.nix;
}
