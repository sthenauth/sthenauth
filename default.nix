{ pkgs ? import <nixpkgs> { }
}:

let
  nix-hs = import (fetchGit {
    url = "https://code.devalot.com/open/nix-hs.git";
    rev = "136d1a5c1e87c2ef5e8050c6b521f4d529645eba";
    ref = "next";
  }) { inherit pkgs; };

in nix-hs {
  cabal = ./sthenauth.cabal;

  overrides = lib: self: super: with lib; rec {
    fused-effects-relude = lib.fetchGit {
      url = "https://code.devalot.com/open/fused-effects-relude.git";
      rev = "97f2864bcc8c1dbbf598c670ac30c6ae8bc20f06";
    };

    inherit (lib.fetchGit {
      url = "https://code.devalot.com/incubator/iolaus.git";
      rev = "5b6547ab081dcdf86b70702b8d39592b3c4a15f0";
    }) iolaus-crypto iolaus-opaleye iolaus-validation;

    zxcvbn-hs = lib.fetchGit {
      url = "https://code.devalot.com/sthenauth/zxcvbn-hs.git";
      rev = "7c05b0c91b4b7f98777cf83ba5b24cdc1d62bfcd";
      ref = "next";
    };

    openid-connect = lib.fetchGit {
      url = "https://code.devalot.com/sthenauth/openid-connect.git";
      rev = "395c65dc777c840d8aa6e8a5c6eb55b80b95a25f";
    };

    haskell-to-elm = super.callCabal2nix "haskell-to-elm"
      (fetchGit {
          url = "https://code.devalot.com/mirrors/haskell-to-elm.git";
          rev = "3ca9ed0098ce909e3bcd10fc4fb9f36d74227a9c";
          ref = "pjones/instances";
      }) {};

    ip = unBreak (dontCheck super.ip);
    wide-word = unBreak (dontCheck (doJailbreak super.wide-word));
    ekg-core = unBreak (dontCheck (doJailbreak super.ekg-core));
  };
}
