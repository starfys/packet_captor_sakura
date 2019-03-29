{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    buildInputs = with pkgs; [
      # For using the makefile
      gnumake
      # Docker compose requires a daemon to exist
      docker_compose
      # Python packages so that vim plugins work
      (pkgs.python3.withPackages (ps: with ps; [
        beautifulsoup4
        lxml
        pylint
        requests
        selenium
        stem
        toml
      ]))
    ];
}
