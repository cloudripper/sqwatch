with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "sqwatch";

  buildInputs = [
    gcc
    gnumake
  ];

  src = ./.;
  buildPhase = "make";
  
  installPhase = ''
    mkdir -p $out/bin
    cp sqwatch $out/bin/sqwatch
  '';
}
