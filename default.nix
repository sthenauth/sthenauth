args@{}:

let
  pkgs = import ./nix/nixpkgs.nix args;

in
{
  sthenauth = import ./sthenauth { inherit pkgs; };
  sthenauth-cli = import ./sthenauth-cli { inherit pkgs; };
  sthenauth-certauth = import ./sthenauth-certauth { inherit pkgs; };
  sthenauth-daemon = import ./sthenauth-daemon { inherit pkgs; };
  sthenauth-servant = import ./sthenauth-servant { inherit pkgs; };
}
