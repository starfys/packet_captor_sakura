// Copyright 2018 Steven Sheffey
// This file is part of packet_captor_sakura.
//
// packet_captor_sakura is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// packet_captor_sakura is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with packet_captor_sakura.  If not, see <https:// www.gnu.org/licenses/>.
extern crate byteorder;
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate flate2;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;

mod bro_types;
mod dataset;
mod entropy;
mod features;
mod flow_aggregator;
mod packet;
mod pcap;

use std::path::Path;

use clap::{App, Arg};
use failure::Error;
use tempdir::TempDir;

use dataset::*;

fn run() -> Result<(), Error> {
    // Start the logger
    drop(env_logger::init());
    // Parse command line arguments
    let matches = App::new("Feature extractor")
        .version("1.0")
        .author("name <email@example.com>")
        .about("Extracts useful features from PCAPs")
        .arg(
            Arg::with_name("data_dir")
                .value_name("DATA_DIR")
                .help("Path to the directory containing data")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("output_dir")
                .value_name("OUTPUT_DIR")
                .help("Path to the directory to output binary encoded data to")
                .required(true)
                .index(2),
        )
        .get_matches();
    // Get the data directory path
    let data_dir: &Path = Path::new(
        matches
            .value_of("data_dir")
            .ok_or_else(|| format_err!("data directory is required"))?,
    );
    // Get the output directory path
    let output_dir: &Path = Path::new(
        matches
            .value_of("output_dir")
            .ok_or_else(|| format_err!("output directory is required"))?,
    );
    // Loading the dataset is bound to the lifetime of the scratch directory, since sometimes we
    // create a temp dir
    info!("Loading the dataset");
    let dataset = Dataset::load(data_dir)?;
    info!("Finished loading the dataset");
    info!("Saving the dataset");
    dataset.save(output_dir)?;
    info!("Finished saving the dataset");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        error!("Error: {:?}", error);
    }
}
