# Copyright 2018 Steven Sheffey 
# This file is part of url_queue.
# 
# url_queue is free software: you can redistribute it and/or modify
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

{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    RUST_LOG="url_queue=debug";
    buildInputs = [(pkgs.python3.withPackages (ps: with ps; [requests])) pkgs.binutils.bintools];
}
