#!/usr/bin/env python3
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
import argparse
from pathlib import Path

import toml

# Parses arguments
arg_parser = argparse.ArgumentParser(
    description="Quick script to parse toml and pull config options")
# Config filename
arg_parser.add_argument(
    'config_filename',
    metavar='CONFIG_FILENAME',
    type=Path,
    help='path to the config file')
# Option
arg_parser.add_argument(
    'option',
    metavar='OPTION',
    type=str,
    help='variable to load from the config')
# Parse the arguments
args = arg_parser.parse_args()

# Read in the config file
config = None
with args.config_filename.open("r") as config_file:
    config = toml.load(config_file)
# Convert the option into a series of keys and traverse the configuration
result = config
for key in args.option.split("."):
    result = result[key]
# Return the result
print(result)
