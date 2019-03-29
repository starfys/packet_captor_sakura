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
use csv;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::iter::FusedIterator;
use std::path::Path;
use std::str::FromStr;

/// Shorthand for an iterator that returns `UrlEntry`
type UrlIterator = Box<Iterator<Item = UrlEntry> + Send>;

/// A URL entry
///
/// similar to those found in the Alexa top 1M dataset
// TODO: zero-copy
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UrlEntry {
    /// ID or rank of the URL
    pub index: u64,
    /// The URL (without a protocol)
    pub url: String,
}

/// Reads URLs from a file with a similar format to Alexa top 1M
pub struct UrlsReader {
    csv_reader: UrlIterator,
}

impl UrlsReader {
    /// Creates a builder for UrlsReader
    pub fn build() -> UrlsReaderBuilder {
        UrlsReaderBuilder::default()
    }
}

/// Builds `UrlsReader`
pub struct UrlsReaderBuilder {
    /// The maximum number of URLs to read
    limit: Option<usize>,
}

impl Default for UrlsReaderBuilder {
    /// Returns a UrlsReaderBuilder with no extra options
    fn default() -> Self {
        UrlsReaderBuilder { limit: None }
    }
}
impl UrlsReaderBuilder {
    /// Sets a limit on the number of URLs to read
    ///
    /// # Parameters
    /// * `limit` - the maximum number of URLs to read
    #[inline]
    #[allow(dead_code)]
    pub fn with_limit(self, limit: usize) -> Self {
        self.with_limit_opt(Some(limit))
    }
    /// Sets an optional limit on the number of URLs to read
    ///
    /// # Parameters
    /// * `limit` - an optional maximum number of URLs to read
    #[inline]
    pub fn with_limit_opt(mut self, limit: Option<usize>) -> Self {
        self.limit = limit;
        self
    }

    /// Reads from some path
    ///
    /// # Parameters
    /// * `path` - path to read the urls from
    /// * `limit` - the maximum number of URLs to read
    pub fn open<P>(self, path: P) -> Result<UrlsReader, io::Error>
    where
        P: AsRef<Path>,
    {
        // Get an object that reads the CSV
        let csv_reader = csv::ReaderBuilder::new()
            // TODO: make this configurable
            .has_headers(false)
            // Fail here if we fail to open the file
            .from_path(path)?
            // Deserialize the records and take ownership
            .into_deserialize()
            // Flatten to remove errors
            // TODO: change to `flatten` when that stabilizes
            .flat_map(|entry| entry);
        // Add limit if given
        let csv_reader: UrlIterator = match self.limit {
            Some(limit) => Box::new(csv_reader.take(limit)),
            None => Box::new(csv_reader),
        };
        // Create our object
        Ok(UrlsReader { csv_reader })
    }
}

impl Iterator for UrlsReader {
    /// Type to return
    type Item = UrlEntry;

    /// Returns the next Item
    fn next(&mut self) -> Option<Self::Item> {
        // Grab the next url from the file
        self.csv_reader.next()
    }
}
