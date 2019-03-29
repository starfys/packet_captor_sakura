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

from proxy import Proxy
from requester import Requester
from utils import build_logger
from worker import Worker


def main(args):
    # Read in the config
    config = None
    with args.config_filename.open('r') as config_file:
        config = toml.load(config_file)

    # Initialize the logger
    logger = build_logger(config)

    logger.info("Starting the worker")

    # Start up a worker
    with Worker("url_queue", 3000, config, tbb_path=args.tbb_path) as worker:
        # Request work until there is no more
        while True:
            # Request work
            work = worker.request_work()
            # Check work
            if work is None:
                break
            # Perform work
            work_report = worker.perform_work(work)
            # Store original error
            error = work_report.get('error')
            # Send work report
            worker.send_report(work_report)
            # Check if error exists
            if error is not None:
                raise error
    logger.info("Worker has been stopped")


# Run the program
if __name__ == "__main__":
    # Get a command line parser
    arg_parser = argparse.ArgumentParser(
        description=
        "Automatically browses using a list of urls, in order to generate traffic"
    )
    # Config filename
    arg_parser.add_argument(
        'config_filename',
        metavar='CONFIG_FILENAME',
        type=Path,
        help='path to the config file')
    # TBB location
    arg_parser.add_argument(
        'tbb_path',
        metavar='TBB_PATH',
        type=Path,
        help='path to the Tor Browser Bundle')
    # Parse the arguments
    args = arg_parser.parse_args()
    # Run the main function
    main(args)
