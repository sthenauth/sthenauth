args@{}:

let
  pkgs = import ./nix/nixpkgs.nix args;

in
{
  sthenauth = import ./sthenauth { inherit pkgs; };
}
