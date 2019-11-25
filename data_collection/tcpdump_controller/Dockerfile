# Copyright 2018 Steven Sheffey
# This file is part of tcpdump_controller.
# 
# tcpdump_controller is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# tcpdump_controller is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with tcpdump_controller.  If not, see <http://www.gnu.org/licenses/>.

FROM rust:1.32

# Package metadata
LABEL version="0.1"
LABEL Description="Server for controlling tcpdump"

# Set up the default user
ENV DEFAULT_USER=user \
    DEFAULT_UID=1000 \
    DEFAULT_GID=1000
ENV USER_HOME="/home/${DEFAULT_USER}"

# Add an untrusted user
RUN groupadd -g "${DEFAULT_GID}" "${DEFAULT_USER}" && \
    useradd -m -u "${DEFAULT_UID}" -g "${DEFAULT_USER}" "${DEFAULT_USER}" && \
    chown -R "${DEFAULT_USER}.${DEFAULT_USER}" "${USER_HOME}" && \
	chmod -R 770 "${USER_HOME}"

# Use the user's home dir for all activities
WORKDIR $USER_HOME

# Copy the source code over
COPY tcpdump_controller tcpdump_controller 
# Give ownership of the source code to the normal user
RUN chown -R "${DEFAULT_USER}.${DEFAULT_USER}" tcpdump_controller

# Switch to untrusted user
USER $DEFAULT_USER

# Build the source
RUN cd tcpdump_controller && \
    cargo build --release && \
    mkdir ../bin && \
    cp target/release/tcpdump_controller ../bin/ && \
    cd .. && \
    rm -r tcpdump_controller
