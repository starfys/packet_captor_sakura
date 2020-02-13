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

# Add in the selenium image so we can copy drivers
FROM selenium/node-firefox:latest as selenium
# Add in tcpdump controller
FROM starfys/tcpdump_controller as tcpdump_controller
# Basis is Ubuntu LTS
FROM ubuntu:18.04

# Package metadata
LABEL version="0.6"
LABEL Description="Browses websites over the internet and tor (using bridges) to generate packet traces"

# Set apt settings, the time zone, and the name of the untrusted user
ENV DEBIAN_FRONTEND=noninteractive \
	DEBCONF_NONINTERACTIVE_SEEN=true \
	TZ="UTC" \
	LOCAL_PREFIX="/usr/local/bin"

# Install apt utils initially to get rid of some warnings
RUN apt-get update -y && \
	apt-get install -y apt-utils 

# Set timezone
RUN apt-get install -y tzdata && \
    echo "${TZ}" > /etc/timezone && \
	dpkg-reconfigure --frontend noninteractive tzdata
# Update
# Install dependencies
# Remove firefox and tor so only their dependencies are installed
RUN apt-get update -y && \
	apt-get upgrade -y && \
	apt-get install -y \
		bzip2 \
        ca-certificates \
        dbus-x11 \
        firefox \
        gnupg \
        libgtk2.0-0 \
		python3 \
        python3-virtualenv \
		sudo \
        tcpdump \
        tor \
        unzip \
        wget \
        xvfb \
        xz-utils && \
	apt-get purge -y \
        firefox \
        tor


# Copy firefox and geckodriver
COPY --from=selenium /opt/firefox-* /opt/firefox
COPY --from=selenium /opt/geckodriver-* /opt/geckodriver
# Add symlinks for firefox and geckodriver
# TODO: less hacky way
RUN ln -sf /opt/firefox/firefox /usr/local/bin/firefox && \
	ln -sf /opt/geckodriver /usr/local/bin/geckodriver 


# Set up the default user
ENV DEFAULT_USER=user \
    DEFAULT_GID=1000 \
    DEFAULT_UID=1000
ENV USER_HOME="/home/${DEFAULT_USER}"
# Add an untrusted user
RUN groupadd -g "${DEFAULT_GID}" "${DEFAULT_USER}" && \
    useradd -m -u "${DEFAULT_UID}" -g "${DEFAULT_USER}" "${DEFAULT_USER}" && \
    chown -R "${DEFAULT_USER}.${DEFAULT_USER}" "${USER_HOME}" && \
	chmod -R 770 "${USER_HOME}"

# Copy all scripts into our VM's local prefix
COPY src/scripts/* "${LOCAL_PREFIX}/"
# Give the untrusted user permission to use sudo to	sniff packets
RUN echo "${DEFAULT_USER} ALL=(ALL) NOPASSWD:SETENV: ${LOCAL_PREFIX}/tcpdump_controller" >> /etc/sudoers.d/tcpdump


# Switch to untrusted user for tor, since that dir needs to be writable
USER $DEFAULT_USER
# Use the user's home dir for all activities
WORKDIR $USER_HOME 

# Set versioning for tor browser
# If tor is blocked on your network, change the mirror to one of the mirrors listed here
# https://www.torproject.org/getinvolved/mirrors.html.en
# You may have to fiddle with the URLs a bit
ENV TOR_DIST_MIRROR="https://www.torproject.org" \
    TBB_PATH="${USER_HOME}/tor_browser" \
	TBB_VERSION="9.0.4" \
	GPG_KEYSERVER="sks-keyservers.net" \
	TBB_KEYID="EF6E 286D DA85 EA2A 4BA7  DE68 4E2C 6E87 9329 8290"

# Uncomment this and manually download the tor browser package if you want to avoid redownloading
# COPY tor_browser.tar.xz .
# Download tor browser from the tor browser website
# Verify it with GPG
# Unzip it
# Delete the zip and gpg files
RUN wget --no-verbose "${TOR_DIST_MIRROR}/dist/torbrowser/${TBB_VERSION}/tor-browser-linux64-${TBB_VERSION}_en-US.tar.xz" -O tor_browser.tar.xz && \
    # wget --no-verbose "${TOR_DIST_MIRROR}/dist/torbrowser/${TBB_VERSION}/tor-browser-linux64-${TBB_VERSION}_en-US.tar.xz.asc" -O tor_browser.tar.xz.asc && \
    # gpg --keyserver "${GPG_KEYSERVER}" --recv-keys "${TBB_KEYID}" && \
    # gpg --verify tor_browser.tar.xz.asc && \
    tar xf tor_browser.tar.xz && \
    mv tor-browser_en-US $TBB_PATH
    # rm tor_browser.tar.xz tor_browser.tar.xz.asc

# Copy tcpdump driver
COPY --from=tcpdump_controller /home/user/bin/tcpdump_controller /usr/local/bin/

# Copy over the python dependencies file 
COPY src/requirements.txt .
# Set up the python3 virtual environment
RUN python3 -m virtualenv -p python3 env && \
    install_python_dependencies.sh env requirements.txt && \
	rm -f install_python_dependencies.sh  requirements.txt && \
	mkdir src

# Copy over the entrypoint and set it
COPY entrypoint.sh . 
ENTRYPOINT ["./entrypoint.sh"]

# Copy over the python source code into the image
COPY src/*.py src/

# Copy over the config file
COPY config.toml .
