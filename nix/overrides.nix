pkgs: lib: self: super:

(import ./overrides-sans-sthenauth.nix lib self super) // {
  sthenauth = import ../sthenauth { inherit pkgs; };
}
