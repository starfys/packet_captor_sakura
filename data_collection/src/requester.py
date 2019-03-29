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
import traceback
from base64 import b64encode

from selenium import webdriver
from selenium.common.exceptions import (SessionNotCreatedException,
                                        TimeoutException)
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class Requester():
    def __init__(self, firefox_config: dict, tor_port: int):
        """
        Constructor
        @param config the configuration to load options from
        """
        # Get the logger
        self.logger = logging.getLogger()
        # Set up firefox to run in headless mode to avoid graphical overhead
        options = FirefoxOptions()
        options.set_headless(True)
        # Store the options
        self.options = options
        # Store params from the config
        self.retries = int(firefox_config["retries"])
        self.wait_tag = firefox_config["wait_tag"]
        self.load_images = int(firefox_config["load_images"])
        self.clean_frequency = int(firefox_config["clean_frequency"])
        self.page_timeout = int(firefox_config["timeout"]["page"])
        self.element_timeout = int(firefox_config["timeout"]["element"])
        # Store tor proxy config
        self.tor_port = tor_port
        # Set driver to None for now
        self.driver = None
        # Initialize some members that will be stored later
        self.mode = None
        self.profile = None

    def start(self, mode: str):
        """
        Initializes the webdriver

        @returns self
        """
        self.logger.info("Starting browser with mode %s", mode)
        # Store the mode
        self.mode = mode
        # Configure profile settings
        profile = FirefoxProfile()
        # Disable CSS since it doesn't make extra requests, and disabling it speeds us up
        profile.set_preference('permissions.default.stylesheet', 2)
        # Disabling images loses us some accuracy to actual browsing, but gains us significant speed
        if not self.load_images:
            profile.set_preference('permissions.default.image', 2)
        # Disable cache
        profile.set_preference("browser.cache.disk.enable", False)
        profile.set_preference("browser.cache.memory.enable", False)
        profile.set_preference("browser.cache.offline.enable", False)
        profile.set_preference("network.http.use-cache", False)
        # Set proxy based on mode
        if mode == "tor":
            profile.set_preference("network.proxy.type", 1)
            profile.set_preference("network.proxy.socks", "127.0.0.1")
            profile.set_preference("network.proxy.socks_port", self.tor_port)
            profile.set_preference("network.proxy.socks_remote_dns", True)
        else:
            profile.set_preference("network.proxy.type", 0)
        # Store profile
        self.profile = profile
        # Store the new mode
        self.mode = mode
        self.logger.info("Starting the webdriver")
        # Build a Firefox webdriver
        self.driver = webdriver.Firefox(
            self.profile, firefox_options=self.options)
        # Set timeouts
        self.driver.set_page_load_timeout(self.page_timeout // 5)
        # self.driver.implicitly_wait(self.page_timeout)
        self.logger.info("Started the webdriver")

    def stop(self):
        self.logger.info("Stopping the webdriver")

        # Close the webdriver
        self.driver.quit()

        # Nullify the reference
        self.driver = None
        self.mode = None
        self.profile = None

        self.logger.info("Stopped the webdriver")

    def request(self, url: str) -> bool:
        """
        Makes a request using the webdriver

        @param driver the webdriver to use
        @param url the url to request
        @return whether the request succeeded
        """
        for retry in range(1, self.retries):
            try:
                # Request the page
                self.driver.get(url)
                # Log the title of whatever loaded
                self.logger.debug("Title of loaded page: %s",
                                  self.driver.title)
                # Break out of the retry loop
                break
            # Ignore broken pipe and try again
            except BrokenPipeError as _:
                self.logger.error(
                    "Geckodriver had a broken pipe error. Retrying request (%d/%d)",
                    retry + 1, self.retries)
                continue
            # Page will probably time out. If it does, just wait for
            # a specific tag
            except TimeoutException:
                try:
                    self.logger.debug("Waiting to find a %s tag",
                                      self.wait_tag)

                    WebDriverWait(self.driver, self.element_timeout).until(
                        EC.presence_of_element_located((By.TAG_NAME,
                                                        self.wait_tag)))

                    self.logger.info("Title of loaded page: %s",
                                     self.driver.title)
                # If we get a timeout exception here, just ignore it
                except TimeoutException:
                    self.logger.warning("Timeout loading %s", url)
                except Exception as exc:
                    self.logger.error(str(exc))
                # Break the loop
                break
            # If the session died, recreate it
            except SessionNotCreatedException:
                # Restart the web driver
                self.stop()
                self.start(self.mode)
                # Do another retry
                continue
            # Just ignore other exceptions
            except Exception as exc:
                # Log the error
                trace = b64encode(traceback.format_exc().encode('utf-8'))
                self.logger.error("Failure in making request: %s, %s", exc,
                                  trace)
                # Break the loop
                break
        # Clean the driver
        self.cleanup()

    def cleanup(self):
        """
        Cleans the driver for future requests
        """
        # Perform cleanup
        try:
            # Go to blank page to stop loading
            self.driver.get("about:mozilla")
            # Because our get timeout is normally low, use an explicit wait
            WebDriverWait(self.driver, self.element_timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "p")))
        # We don't handle SessionNotCreatedException here
        except Exception as exc:
            self.logger.error("Failed to cleanup: %s %s", exc,
                              traceback.format_exc())
