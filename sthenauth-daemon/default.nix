{ pkgs ? import ../nix/nixpkgs.nix { }
}:

pkgs.nix-hs {
  cabal = ./sthenauth-daemon.cabal;
  overrides = lib: self: super:
    (import ../nix/overrides.nix pkgs lib self super) // {
      sthenauth-certauth = import ../sthenauth-certauth { inherit pkgs; };
      sthenauth-cli = import ../sthenauth-cli { inherit pkgs; };
      sthenauth-servant = import ../sthenauth-servant { inherit pkgs; };
    };
}
