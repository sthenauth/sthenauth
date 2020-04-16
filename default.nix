args@{}:

let
  pkgs = import ./nix/nixpkgs.nix args;

in
{
  sthenauth = import ./sthenauth { inherit pkgs; };
  sthenauth-certauth = import ./sthenauth-certauth { inherit pkgs; };
  sthenauth-servant = import ./sthenauth-servant { inherit pkgs; };
}
