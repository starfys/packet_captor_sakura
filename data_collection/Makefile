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
all: build


CAPTURE_SERVICE=capture
URL_SERVICE=url_queue

CAPTURE_SCALE=8

build: build_tcpdump_controller
	docker-compose build $(SERVICE_NAME)
build_tcpdump_controller:
	make -C tcpdump_controller

up: build
	# Run image
	docker-compose up -d --force-recreate --scale $(URL_SERVICE)=1 --scale $(CAPTURE_SERVICE)=1
scale: build
	# Run image
	docker-compose up -d --force-recreate --scale $(URL_SERVICE)=1 --scale $(CAPTURE_SERVICE)=$(CAPTURE_SCALE)
logs:
	docker-compose logs -f
down:
	docker-compose down
