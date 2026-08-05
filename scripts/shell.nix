{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = [
    pkgs.libpcap
    pkgs.pkg-config
  ];
}

