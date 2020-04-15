self: super:

{
  nix-hs = import ./nix-hs.nix { pkgs = super; };
}
