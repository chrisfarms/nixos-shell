{
  nixpkgs ? <nixpkgs>, system ? builtins.currentSystem
}:

with import nixpkgs { inherit system; };

stdenv.mkDerivation {
  name = "nixos-shell";
  src = ./.;
  buildInputs = [ go ];
  phases = [ "buildPhase" ];
  buildPhase = 
    ''
    mkdir -p $out/bin
    GOPATH=$src go build -o $out/bin/nixos-shell nixos-shell
    '';
}
