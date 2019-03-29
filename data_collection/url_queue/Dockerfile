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

FROM rust:1.32

# Package metadata
LABEL version="0.1"
LABEL Description="API for retrieving new URLs to navigate to"

# Install some extra packages
RUN apt-get update -y && \
	apt-get install -y sudo unzip

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

# Download the alexa top 1m
ENV ALEXA_PATH="${USER_HOME}/alexa-1m.csv"
RUN wget --no-verbose "https://s3.amazonaws.com/alexa-static/top-1m.csv.zip" && \
	unzip top-1m.csv.zip && \ 
	rm top-1m.csv.zip && \
	mkdir data && \
	mv top-1m.csv "${ALEXA_PATH}"

# Copy the source code over
COPY url_queue url_queue
# Give ownership of the source code to the normal user
RUN chown -R "${DEFAULT_USER}.${DEFAULT_USER}" url_queue

# Switch to untrusted user
USER $DEFAULT_USER

# Build the source
RUN cd url_queue && \
    cargo build --release && \
    # cargo build && \
    mkdir ../bin && \
    cp target/release/url_queue ../bin/ && \
    # cp target/debug/url_queue ../bin/ && \
    cd .. && \
    rm -r url_queue

# Set environment variables so logs are shown
ENV RUST_LOG="url_queue=info"

# Switch to root for copying over and running entry 
USER root 

# Copy over entrypoint script
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
# Run entry point as root
# Set up the entrypoint
ENTRYPOINT ["./entrypoint.sh"]

# Copy over the config
COPY config.toml .
