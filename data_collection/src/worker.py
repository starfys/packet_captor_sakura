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
import time
import typing
from pathlib import Path

import requests

from proxy import Proxy
from requester import Requester
from tcpdump import TcpDump, TcpDumpError


class Worker():
    def __init__(self, host: str, port: int, config: dict, tbb_path):
        """
        Stores the work queue URL and various configuration options
        """
        # Create the work url
        self.work_url = "http://{}:{}".format(host, port)
        # Store number of times work is completed per type
        self.work_type_counts = {'normal': 0, 'tor': 0}
        # Create a requests session
        self.session = requests.Session()
        # Disable keepalive
        self.session.keep_alive = False
        # Get a logger
        self.logger = logging.getLogger()
        # Store given config
        self.config = config
        self.tbb_path = tbb_path
        # Initialize members that will be created later
        self.client_id = None
        self.tcpdump = None
        self.proxy = None
        self.requester = None

    def __enter__(self):
        """
        Ensures server is available
        Requests and stores a client ID from the server
        Gets a connection to the tcpdump daemon
        :throws Exception: if the client ID request fails
        """
        # Send requests to the URLs service until the status
        # page returns a response
        waiting = True
        while waiting:
            try:
                self.logger.info("Attempting to contact work queue")
                self.session.get("{}/status".format(self.work_url))
                waiting = False
            except Exception as _:
                self.logger.info(
                    "Attempt to contact work queue failed. Retrying")
        # Request a client ID
        # TODO: look into renaming this "register"
        self.logger.info("Registering client with server")
        # TODO: work types as part of config
        response = self.session.post(
            "{}/client/add".format(self.work_url),
            json={'work_types': ['tor', 'normal']})
        # Parse response as json
        response = response.json()
        # Extract client id from response
        if response['success']:
            self.client_id = response['client_id']
        else:
            raise Exception(response['error'])
        # Start up a connection to the tcpdump daemon
        # TODO: parameterize socket path
        self.tcpdump = TcpDump('/tmp/tcpdump.socket')
        # Instantiate proxy object
        self.proxy = Proxy(self.tbb_path, self.config["tor"])
        # Instantiate requester object
        self.requester = Requester(self.config["firefox"],
                                   self.config["tor"]["port"])
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Informs the server that the client has stopped
        :param exc_type:
        :param exc_value:
        :param traceback:
        """
        # If the program completed without error
        if exc_type is None:
            self.logger.info("Worker program finished without error")
        else:
            # Log the error
            self.logger.error("%s %s %s", exc_type, exc_value, traceback)
        # Indicate to the server that the client has stopped
        self.logger.info("Deregistering client from server")
        self.session.post(
            "{}/client/remove".format(self.work_url),
            json={'client_id': self.client_id})
        # Stop the tcpdump daemon
        self.tcpdump.shutdown()

    def request_work(self):
        """
        Requests a piece of work from the server
        """
        # Make a request to the server to get a URL to navigate to
        try:
            # Make a request for work
            response = self.session.post(
                "{}/work/get".format(self.work_url),
                json={'client_id': self.client_id})
            # 204 means no more URLs
            if response.status_code == 204:
                self.logger.info("No more URLs")
                return None
            # This will throw an exception if it fails, which is handled below
            work = response.json()
            return work
        except Exception as exc:
            self.logger.error("Failed to request work: %s", exc)
            return None

    def perform_work(self, work: dict):
        """
        Performs a piece of work given by the server
        :param work: work as received from the server
        """
        # Extract required variables from work
        mode = work["work_type"]
        # Once type is extracted, limit the scope of work
        work = work["work"]
        filename = work["filename"]
        url = "https://{}".format(work["url"])
        global_index = work["index"]
        # Set work type counter
        self.work_type_counts[mode] += 1
        # Scoped variables set inside try block
        error = None
        fatal = False
        # Store timestamp
        start_time = int(time.time() * 1e9)
        try:
            # Start packet capture
            self.tcpdump.start(filename)
            # Start proxy
            self.proxy.start(mode)
            # Start requester
            self.requester.start(mode)

            # Perform request in requester
            self.logger.info(
                "Navigating to %s in %s mode (local: %d) (global: %d)", url,
                mode, self.work_type_counts[mode], global_index)
            self.requester.request(url)

            # End requester
            self.requester.stop()
            # End proxy
            self.proxy.stop()
            # End packet capture
            self.tcpdump.stop()
        except TcpDumpError as err:
            self.logger.error(str(err))
            error = err
            fatal = True
        except Exception as err:
            self.logger.error(str(err))
            error = err
        # Store ending timestamp
        finish_time = int(time.time() * 1e9)
        # Create report
        report = {
            'success': error is None,
            'work_type': mode,
            'work': work,
            'type_index': self.work_type_counts[mode],
            'start_time': start_time,
            'finish_time': finish_time,
            # This will be stripped
            'fatal': fatal
        }
        # Store the error if given
        if error is not None:
            report['error'] = str(error)
        # Return report
        return report

    def send_report(self, report: dict):
        # Stringify error
        if 'error' in report:
            report['error'] = str(report['error'])
        # Send the report
        self.session.post("{}/work/report".format(self.work_url), json=report)
        # FIXME: Make a dummy request to the server. to enforce the shutdown
        # Allow this to fail
        try:
            self.session.post("{}/status".format(self.work_url))
        except:
            pass
