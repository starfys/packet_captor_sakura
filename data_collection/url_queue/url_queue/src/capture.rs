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
use std::cmp::Ordering;
use std::fmt;
use std::io;
use std::path::PathBuf;


use hex;
use rand::{self, Rng};

use config::Config;
use service::WorkQueueService;
use shutdown;
use url::{UrlEntry, UrlsReader};

#[derive(Copy, Clone, Ord, Debug, Eq, Hash, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum CaptureWorkType {
    #[serde(rename = "normal")]
    Normal,
    #[serde(rename = "tor")]
    Tor,
}
impl fmt::Display for CaptureWorkType {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use self::CaptureWorkType::*;
        write!(
            formatter,
            "{}",
            match *self {
                Normal => "normal",
                Tor => "tor",
            }
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, Deserialize, Serialize)]
pub struct CaptureWork {
    pub index: u64,
    pub url: String,
    pub filename: PathBuf,
}

impl PartialOrd for CaptureWork {
    /// Custom comparator used so that lower indexes appear as higher priority work
    ///
    /// # Parameters
    /// * `other` - `CaptureWork` to compare against
    fn partial_cmp(&self, other: &CaptureWork) -> Option<Ordering> {
        self.index
            .partial_cmp(&other.index)
            .map(|ord| ord.reverse())
    }
}

impl From<UrlEntry> for CaptureWork {
    /// Constructor that creates a new piece of capture work
    ///
    /// filename is randomly generated
    ///
    /// # Parameters
    /// * `url` - Url the worker should navigate to
    fn from(url_entry: UrlEntry) -> Self {
        // Get access to the RNG
        let mut rng = rand::thread_rng();
        // Generate 32 random bytes
        let random_bytes: [u8; 32] = rng.gen();
        // Hex-encode the bytes
        let filename = PathBuf::from(hex::encode(random_bytes)).with_extension("pcap");
        // Create a work item
        CaptureWork {
            index: url_entry.index,
            url: url_entry.url,
            filename,
        }
    }
}

impl<'a> WorkQueueService<'a, CaptureWorkType, CaptureWork> {
    /// Creates a new work queue service using options from the config
    ///
    /// # Parameters
    /// * `config` - config to load
    pub fn from_config(config: &Config) -> Result<(Self, shutdown::ServerShutdown), io::Error> {
        // Read URLs and generate work
        let work = UrlsReader::build()
            .with_limit_opt(config.num_urls)
            .open(config.urls_path.clone())?
            .flat_map(|url_entry| {
                // Create work using both types
                [CaptureWorkType::Normal, CaptureWorkType::Tor]
                    .into_iter()
                    .cloned()
                    .map(move |work_type| {
                        let url_entry = url_entry.clone();
                        (work_type, CaptureWork::from(url_entry))
                    })
            });
        // Create the service
        WorkQueueService::new(work, config.report_path.clone())
    }
}
