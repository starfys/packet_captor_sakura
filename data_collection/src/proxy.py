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
import logging
import os
import typing
from pathlib import Path

from stem import process as stem_process


class Proxy():
    def __init__(self, tbb_path, tor_config: dict):
        # Get the logger
        self.logger = logging.getLogger()
        # ==============================
        # Initialize tor stuff
        # ==============================
        # Get path to tor folder
        tor_path = tbb_path / "Browser" / "TorBrowser" / "Tor"
        # Path to the tor daemon
        self.tor_executable_path = tor_path / "tor"
        # Meek client
        meek_client_path = tor_path / "PluggableTransports" / "meek-client"
        # Meek client helper
        meek_client_tb_path = tor_path / "PluggableTransports" / "meek-client-torbrowser"
        # Obfsproxy path
        obfsproxy_path = tor_path / "PluggableTransports" / "obfs4proxy"
        # Set the bridge
        # Build the config
        self.tor_config = {
            "UseBridges": "1",
            "ClientTransportPlugin":
            "meek_lite exec {}".format(obfsproxy_path.absolute()),
            "Bridge": tor_config["bridge"],
            'Log': [
                'NOTICE stdout',
                'ERR file {}'.format(tor_config["log_path"]),
            ]
        }
        # Set environment to use tor directory for dynamic libs
        if "LD_LIBRARY_PATH" in os.environ:
            os.environ["LD_LIBRARY_PATH"] = "{}:{}".format(
                os.environ["LD_LIBRARY_PATH"], str(tor_path))
        else:
            os.environ["LD_LIBRARY_PATH"] = str(tor_path)
        # No tor process on construction
        self.tor_process = None
        # Whether tor has not already been started once
        self.first_tor_run = True

        # Store the timeouts
        self.tor_timeouts = tor_config["timeout"]

        # Initially, there is no mod
        self.mode = None

    def start(self, mode: str):
        """
        Starts tor if the given mode is tor
        """
        self.logger.info("Starting the proxy in %s mode", mode)
        # Store the mode
        self.mode = mode
        # Start tor
        if mode == "tor":
            # Calculate the timeout based on which run
            # If the first run flag is set, unset it
            timeout = None
            if self.first_tor_run:
                timeout = self.tor_timeouts["initial"]
                self.first_tor_run = False
            else:
                timeout = self.tor_timeouts["regular"]
            self.logger.info("Starting TOR")
            # Launch the tor process
            self.tor_process = stem_process.launch_tor_with_config(
                config=self.tor_config,
                tor_cmd=str(self.tor_executable_path),
                timeout=timeout,
                take_ownership=True,
                # init_msg_handler = print
            )
        elif mode == "normal":
            self.logger.info("Starting null proxy")
        else:
            raise Exception(f"Invalid mode: {mode}")
        self.logger.info("Started the proxy")
        # Return nothing
        return self

    def stop(self):

        self.logger.info("Stopping the proxy")

        if self.mode == "tor":
            if self.tor_process is None:
                self.logger.warning(
                    "Cannot kill tor process that does not exist")
            else:
                # Kill tor
                self.logger.info("Stopping TOR")
                self.tor_process.terminate()
                self.tor_process.wait()
                self.logger.info("Stopped TOR")

                # Clear the process variable
                self.tor_process = None
        elif self.mode == "normal":
            self.logger.info("Stopping null proxy")

        # Clear the mode
        self.mode = None

        self.logger.info("Stopped the proxy")
