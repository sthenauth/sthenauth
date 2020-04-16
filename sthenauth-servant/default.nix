{ pkgs ? import ../nix/nixpkgs.nix { }
}:

pkgs.nix-hs {
  cabal = ./sthenauth-servant.cabal;
  overrides = lib: self: super:
    (import ../nix/overrides.nix pkgs lib self super) // {
      sthenauth-certauth = import ../sthenauth-certauth { inherit pkgs; };
    };
}
