{ sources ? import ./sources.nix }:

lib: self: super:

with lib;

rec {
  ##############################################################################
  # Packages that I own or have patched:
  addy = import sources.addy { inherit (lib) pkgs; };

  fused-effects-relude =
    import sources.fused-effects-relude { inherit (lib) pkgs; };

  inherit (import sources.iolaus { inherit (lib) pkgs; })
    iolaus-crypto iolaus-opaleye iolaus-validation;

  byline = import sources.byline { inherit (lib) pkgs; };

  zxcvbn-hs = import sources.zxcvbn-hs { inherit (lib) pkgs; };

  openid-connect = import sources.openid-connect { inherit (lib) pkgs; };

  haskell-to-elm =
    super.callCabal2nix "haskell-to-elm" (sources.haskell-to-elm) { };

  ##############################################################################
  # Latest versions of some packages:
  ormolu = (import sources.ormolu {
    inherit (lib) pkgs;
    ormoluCompiler = lib.compilerName;
  }).ormolu;

  ghcide = import sources.ghcide-nix { ghc = lib.compilerName; };

  ##############################################################################
  # Un-break some packages:
  ip = unBreak (dontCheck super.ip);
  wide-word = unBreak (dontCheck (doJailbreak super.wide-word));
  ekg-core = unBreak (dontCheck (doJailbreak super.ekg-core));
}
