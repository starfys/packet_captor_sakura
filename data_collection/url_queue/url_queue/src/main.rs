// Copyright 2018 Steven Sheffey
// This file is part of url_queue.
//
// url_queue is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// url_queue is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with url_queue.  If not, see <http://www.gnu.org/licenses/>.
#![allow(unused_imports)]

extern crate clap;
extern crate csv;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate hex;
extern crate http;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate toml;

mod capture;
mod config;
mod service;
mod shutdown;
mod url;
mod work;

use std::io;
use std::iter::FromIterator;
use std::sync::{Arc, Mutex};

use clap::{App, Arg};
use hyper::header;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Response, Server, StatusCode};

use capture::{CaptureWork, CaptureWorkType};
use service::WorkQueueService;
use url::UrlsReader;

fn main() -> Result<(), io::Error> {
    // Initiate logger
    env_logger::init();
    // Parse command line arguments
    let matches = App::new("URL Queue")
        .version("0.1")
        .author("Steven Sheffey <srs6p@mtmail.mtsu.edu>")
        .about("Serves URLs from a file")
        .arg(
            Arg::with_name("config_file")
                .value_name("CONFIG_FILE")
                .help("Path to the config file")
                .required(true)
                .takes_value(true),
        )
        .get_matches();
    // Get the path to the config file
    let config_file = matches.value_of("config_file").unwrap();
    // Load the config
    let config = config::Config::load(config_file).unwrap();
    // Create a server from generated work
    let (service, shutdown_fut) = WorkQueueService::from_config(&config)?;
    // Create a server that listens on the given address
    let server = Server::bind(&config.listen_addr)
        .serve(service)
        .with_graceful_shutdown(shutdown_fut)
        .map_err(|err| error!("Error spawning service: {}", err));
    // Run the server
    hyper::rt::run(server);
    // Return success from main
    Ok(())
}
