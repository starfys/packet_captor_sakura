#!/bin/bash
# Copyright 2018 Steven Sheffey 
# This file is part of packet_captor_sakura.
# 
# packet_captor_sakura is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# packet_captor_sakura is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with packet_captor_sakura.  If not, see <http://www.gnu.org/licenses/>.

set -eu

# Start the server
export RUST_LOG=tcpdump_controller=debug
sudo -E tcpdump_controller &

# Get whicah config file we're using
export CONFIG_PATH="$(pwd)/${CONFIG_FILENAME}"
# Activate the python environment
export PS1=""
source ./env/bin/activate


export SRC_DIR="$(pwd)/src"
cd "$TBB_PATH/Browser"

# Generate some data by downloading many webpages over meek 
xvfb-run -a python3 -u "${SRC_DIR}/main.py" "${CONFIG_PATH}" "${TBB_PATH}" &

# Wait for the python script to finish (or be interrupted)
wait $!
