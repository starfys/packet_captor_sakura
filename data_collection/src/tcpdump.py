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
import socket
import struct
import typing
from pathlib import Path


class TcpDump():
    """
    Interfaces with the TCPDUMP controller daemon
    """

    def __init__(self, socket_filename):
        """
        Constructor
        :param socket_filename: path to the socket used to communicate with
                                the daemon
        """
        # Get the logger
        self.logger = logging.getLogger()
        # Connect to the tcpdump service socket
        self.tcpdump = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.tcpdump.connect(socket_filename)
        self.tcpdump.settimeout(60)

    def start(self, filename: str):
        """
        Starts tcpdump
        :param url: filename for the pcap file
        """
        # Create the filename
        # TODO: only pass filename and have tcpdump controller handle the path prefix
        filename = Path("/pcap_data") / filename
        # Get filename as bytes
        filename = str(filename).encode('utf-8')

        self.logger.info("Starting tcpdump")

        # Send request over socket
        msg = struct.pack("<BI", 0x00, len(filename)) + filename
        self.tcpdump.send(msg)

        # Handle response over socket
        response = self.tcpdump.recv(1)[0]
        if response == 0x00:
            self.logger.info("Successfully started tcpdump")
        elif response == 0x01:
            raise TcpDumpError("Failed to start tcpdump")
        else:
            raise TcpDumpError("Invalid response from starting tcpdump")

    def stop(self):
        """
        Stops tcpdump
        """
        # Send request over socket
        self.tcpdump.send(b'\x01')
        # Handle response over socket
        response = self.tcpdump.recv(1)[0]
        if response == 0x00:
            self.logger.info("Successfully stopped tcpdump")
        elif response == 0x01:
            raise TcpDumpError("failed to stop tcpdump")
        else:
            raise TcpDumpError(
                "Received invalid response code from tcpdump controller")

    def shutdown(self):
        """
        Shuts down the tcpdump controller
        """
        # Send request over socket
        self.tcpdump.send(b'\x02')
        # Handle response over socket
        response = self.tcpdump.recv(1)[0]
        if response == 0x00:
            self.logger.info("Successfully shutdown tcpdump")
        elif response == 0x01:
            raise TcpDumpError("Failed to shutdown tcpdump")
        else:
            raise TcpDumpError(
                "Received invalid response code from tcpdump controller")


class TcpDumpError(Exception):
    pass
