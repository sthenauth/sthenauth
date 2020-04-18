{ pkgs ? import ../nix/nixpkgs.nix { }
}:

pkgs.nix-hs {
  cabal = ./sthenauth-cli.cabal;
  overrides = import ../nix/overrides.nix pkgs;
}
