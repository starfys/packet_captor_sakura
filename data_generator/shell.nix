{ pkgs ? import <nixpkgs-unstable> {} }:
  pkgs.mkShell {
    RUST_LOG="data_generator=debug";
    buildInputs = with pkgs; [
      binutils.bintools
      zeek
      gcc
    ];
  }
