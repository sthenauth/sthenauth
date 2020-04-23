args@{}:

let
  pkgs = import ./nix/nixpkgs.nix args;

in pkgs.nix-hs {
  cabal = {
    sthenauth = ./sthenauth/sthenauth.cabal;
    sthenauth-certauth = ./sthenauth-certauth/sthenauth-certauth.cabal;
    sthenauth-cli = ./sthenauth-cli/sthenauth-cli.cabal;
    sthenauth-daemon = ./sthenauth-daemon/sthenauth-daemon.cabal;
    sthenauth-servant = ./sthenauth-servant/sthenauth-servant.cabal;
  };

  overrides = import ./nix/overrides.nix;
}
