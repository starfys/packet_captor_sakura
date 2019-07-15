# Copyright 2018 Steven Sheffey 
# This file is part of packet_captor_sakura.
# 
# packet_captor_sakura is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# url_queue is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with url_queue.  If not, see <http://www.gnu.org/licenses/>.
{ pkgs ? import <nixpkgs> {}, pkgs_unstable ? import <nixpkgs-unstable> {}, pythonPackages ? pkgs_unstable.python3Packages }:
let
  kernels = [];
  additionalExtensions = [
    "@jupyter-widgets/jupyterlab-manager"
  ];
in
pkgs.mkShell rec {
  buildInputs = [
    # Base Packages
    pythonPackages.jupyterlab pkgs.nodejs
  ] ++
  # Python deps
  [
    pythonPackages.matplotlib
    pythonPackages.numpy
    pythonPackages.pandas
    pythonPackages.pytorchWithCuda
    pythonPackages.ipywidgets
    pythonPackages.scikitlearn
    pythonPackages.scipy
    pythonPackages.seaborn
    pythonPackages.tqdm
  ] ++
  # Kernels
  kernels;

  shellHook = ''
    export CUDA_HOME="${pkgs.cudatoolkit}"
    TEMPDIR=$(mktemp -d -p /tmp)
    mkdir -p $TEMPDIR
    cp -r ${pythonPackages.jupyterlab}/share/jupyter/lab/* $TEMPDIR
    chmod -R 755 $TEMPDIR
    echo "$TEMPDIR is the app directory"

    # kernels
    export JUPYTER_PATH="${pkgs.lib.concatMapStringsSep ":" (p: "${p}/share/jupyter/") kernels}"

    # labextensions
    ${pkgs.stdenv.lib.concatMapStrings
         (s: "jupyter labextension install --no-build --app-dir=$TEMPDIR ${s}; ")
         (pkgs.lib.unique
           ((pkgs.lib.concatMap
               (d: pkgs.lib.attrByPath ["passthru" "jupyterlabExtensions"] [] d)
               buildInputs) ++ additionalExtensions))  }
    jupyter lab build --app-dir=$TEMPDIR
    # start jupyterlab
    jupyter lab --app-dir=$TEMPDIR
  '';
}
