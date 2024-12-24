let
  nixpkgs = import <nixpkgs> {};
  sqwatch = import ./default.nix;
in
  nixpkgs.mkShell {
    buildInputs = [
      sqwatch
    ];
  }
