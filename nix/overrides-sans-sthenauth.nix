lib: self: super:

with lib;

let
  lsp = fetchGit {
    url = "https://github.com/alanz/haskell-lsp.git";
    rev = "c19ed85e9da8516784415c7144331cabe9e89bf8"; # 0.21
  };
in

rec {
  #
  #
  # Packages that I own or have patched:
  #
  #
  fused-effects-relude = lib.fetchGit {
    url = "https://code.devalot.com/open/fused-effects-relude.git";
    rev = "97f2864bcc8c1dbbf598c670ac30c6ae8bc20f06";
  };

  inherit (lib.fetchGit {
    url = "https://code.devalot.com/incubator/iolaus.git";
    rev = "5b6547ab081dcdf86b70702b8d39592b3c4a15f0";
  }) iolaus-crypto
     iolaus-opaleye
     iolaus-validation;

  byline = lib.fetchGit {
    url = "https://code.devalot.com/open/byline.git";
    rev = "486d8177b36288c6c607e5dcc34aae940b9ab031";
  };

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

  #
  #
  # Latest versions of some packages:
  #
  #
  ormolu = (import (fetchGit {
      url = "https://github.com/tweag/ormolu.git";
      rev = "683cbeacf5334cd8615b49d31a8ecf35ec20cafe";
    }) {
      pkgs = lib.pkgs;
      ormoluCompiler = lib.compilerName;
    }).ormolu;

  ghcide = (import (fetchGit {
    url = "https://code.devalot.com/pjones/ghcide-nix.git";
    rev = "471990016e47f6eaab5d6aeeb2da6f58aa581bb7";
  })) {};

  #
  #
  # Un-break some packages:
  #
  #
  ip = unBreak (dontCheck super.ip);
  wide-word = unBreak (dontCheck (doJailbreak super.wide-word));
  ekg-core = unBreak (dontCheck (doJailbreak super.ekg-core));
}
