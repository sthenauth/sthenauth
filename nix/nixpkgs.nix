{ commit ? "a2e06fc3423c4be53181b15c28dfbe0bcf67dd73"
}:

import (builtins.fetchTarball {
  name = "nixpkgs-${commit}";
  url  = "https://github.com/nixos/nixpkgs/archive/${commit}.tar.gz";
}) {
  overlays = [
    (import ./overlay.nix)
  ];
}
