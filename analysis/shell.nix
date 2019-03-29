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
let
  unstable = import <nixos-unstable> {};
in
{ pkgs ? import <nixpkgs> {} }:
  unstable.mkShell {
    buildInputs = [
      (master.python37.withPackages (ps: with ps; [
        pip
        virtualenv
        jupyterlab
        matplotlib
        numpy
        pandas
	pytorchWithoutCuda
        scikitlearn
        scipy
        seaborn
	tqdm
        #tensorflowWithoutCuda
        #tensorflow-tensorboard
      ]))];
}
