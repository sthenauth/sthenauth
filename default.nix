{ sources ? import ./nix/sources.nix, pkgs ? import sources.nixpkgs { }
, ghc ? "default" }:

let nix-hs = pkgs.callPackage ./nix/nix-hs.nix { };

in nix-hs {
  cabal = {
    sthenauth = ./sthenauth/sthenauth.cabal;
    sthenauth-certauth = ./sthenauth-certauth/sthenauth-certauth.cabal;
    sthenauth-cli = ./sthenauth-cli/sthenauth-cli.cabal;
    sthenauth-daemon = ./sthenauth-daemon/sthenauth-daemon.cabal;
    sthenauth-servant = ./sthenauth-servant/sthenauth-servant.cabal;
  };

  compiler = ghc;
  overrides = pkgs.callPackage ./nix/overrides.nix { };
}
