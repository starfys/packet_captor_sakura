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
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::iter::FromIterator;

/// Handles work
#[derive(Clone)]
pub struct WorkQueue<T, W> {
    /// Priority queue for each work type
    work: HashMap<T, BinaryHeap<W>>,
    /// Records client IDs and what work types they support
    /// in order of preference
    clients: HashMap<u64, Vec<T>>,
    /// Monotonic counter for client IDs
    cur_client_id: u64,
}

impl<T, W> FromIterator<(T, W)> for WorkQueue<T, W>
where
    T: Eq + Hash,
    W: Clone + Ord,
{
    /// Creates a work queue from an iterator of work
    ///
    /// # Parameters
    /// * `iter` - iterator over work types and items
    fn from_iter<I: IntoIterator<Item = (T, W)>>(iter: I) -> Self {
        // Create the work map
        let mut work: HashMap<T, BinaryHeap<W>> = HashMap::new();
        // Insert work
        for (work_type, work_item) in iter {
            // Insert each work element into the work map
            // Get access to the work queue for this work type
            work.entry(work_type)
                // Create a new queue if required
                .or_insert_with(BinaryHeap::new)
                // Add work to the queue
                .push(work_item);
        }
        // Create the work queue
        WorkQueue {
            work,
            clients: HashMap::new(),
            cur_client_id: 0,
        }
    }
}

impl<T, W> WorkQueue<T, W> {
    /// Work queue
    /// Adds a client
    pub fn add_client(&mut self, work_types: Vec<T>) -> u64 {
        // Increment the current ID
        self.cur_client_id += 1;
        // Add a client using the current ID
        self.clients.insert(self.cur_client_id, work_types);
        // Return the new client's ID
        self.cur_client_id
    }
    /// Removes a client
    ///
    /// # Parameters
    /// * `client_id` - ID of the client to remove
    pub fn remove_client(&mut self, client_id: u64) {
        self.clients.remove(&client_id);
    }
    /// Returns the number of active clients
    pub fn num_clients(&self) -> usize {
        self.clients.len()
    }
}

impl<T, W> WorkQueue<T, W>
where
    T: Clone + Eq + Hash,
    W: Ord,
{
    /// Retrieves work from the queue
    ///
    /// # Parameters
    /// * `client_id` - Client to request work as
    pub fn request_work(&mut self, client_id: u64) -> Option<(T, W)> {
        // Get mutable reference to work queues
        let work = &mut self.work;
        // Get the client's preferred work types
        self.clients
            .get(&client_id)?
            // Convert from vec to iterator
            .iter()
            .cloned()
            // Get the work queue for the given work type
            .flat_map(|work_type: T| {
                work.get_mut(&work_type)?
                    .pop()
                    .map(|work_item| (work_type, work_item))
            })
            // Grab the first work item
            .next()
    }
    /// Adds work to the queue
    ///
    /// # Parameters
    /// * `work_type` - Type of work to add
    /// * `work_item` - Work to add
    pub fn add_work(&mut self, work_type: T, work_item: W) {
        // Get access to the work queue for this work type
        self.work
            .entry(work_type)
            // Create a new queue if required
            .or_insert_with(BinaryHeap::new)
            // Add work to the queue
            .push(work_item);
    }
}

/// Represents the HTTP request for
/// POST /work/get
#[derive(Deserialize)]
pub struct WorkRequest {
    pub client_id: u64,
}
/// Represents the HTTP response for
/// POST /work/get
#[derive(Serialize)]
pub struct WorkResponse<T, W> {
    pub success: bool,
    pub work_type: T,
    pub work: W,
    pub error: Option<String>,
}
/// Represents the HTTP request for
/// POST /work/report
#[derive(Debug, Deserialize, Serialize)]
pub struct WorkReportRequest<T, W> {
    /// Whether the worker succeeded
    pub success: bool,
    /// Type of work attempted
    pub work_type: T,
    /// Work completed
    pub work: W,
    /// Indicates that this is the Nth reported work for the given type by the worker
    pub type_index: u64,
    /// Timestamp the work was started (unix timestamp in nanoseconds)
    pub start_time: u64,
    /// Timestamp the work finished (unix timestamp in nanoseconds)
    pub finish_time: u64,
}

/// Represents the HTTP response for
/// POST /work/report
#[derive(Serialize)]
pub struct WorkReportResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Represents the HTTP request for
/// POST /client/add
#[derive(Deserialize)]
pub struct AddClientRequest<T> {
    pub work_types: Vec<T>,
}
/// Represents the HTTP response for
/// POST /client/add
#[derive(Serialize)]
pub struct AddClientResponse {
    pub success: bool,
    pub client_id: u64,
    pub error: Option<String>,
}
/// Represents the HTTP request for
/// POST /client/remove
#[derive(Deserialize)]
pub struct RemoveClientRequest {
    pub client_id: u64,
}
/// Represents the HTTP response for
/// POST /client/remove
#[derive(Serialize)]
pub struct RemoveClientResponse {
    pub success: bool,
    pub error: Option<String>,
}
