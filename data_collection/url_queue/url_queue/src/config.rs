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

use failure::Fail;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use toml;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub urls_path: PathBuf,
    pub num_urls: Option<usize>,
    pub report_path: PathBuf,
}

impl Config {
    pub fn load<P>(path: P) -> Result<Self, ConfigLoadError>
    where
        P: AsRef<Path>,
    {
        // Open the file
        let config_file = File::open(path)?;
        let mut reader = BufReader::new(config_file);
        // Read in the entire file
        let mut contents: Vec<u8> = Vec::with_capacity(200);
        reader.read_to_end(&mut contents)?;
        // Parse the config
        Ok(toml::from_slice(&contents)?)
    }
}

/// Custom error that handles all cases of config loading
#[derive(Debug, Fail)]
pub enum ConfigLoadError {
    #[fail(display = "error opening file: {}", error)]
    FileOpen { error: io::Error },
    #[fail(display = "error parsing toml: {}", error)]
    TomlParse { error: toml::de::Error },
}

// TODO: make this implementation private
impl From<io::Error> for ConfigLoadError {
    /// Wraps io::Error
    ///
    /// # Parameters
    /// * `error` - an io::Error
    fn from(error: io::Error) -> Self {
        ConfigLoadError::FileOpen { error }
    }
}
// TODO: make this implementation private
impl From<toml::de::Error> for ConfigLoadError {
    /// Wraps io::Error
    ///
    /// # Parameters
    /// * `error` - an io::Error
    fn from(error: toml::de::Error) -> Self {
        ConfigLoadError::TomlParse { error }
    }
}
