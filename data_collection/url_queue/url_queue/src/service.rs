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
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::error;
use std::fs::{File, OpenOptions};
use std::hash::Hash;
use std::io::{self, BufWriter, Write};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use futures::sync::oneshot::{Receiver, Sender};
use futures::{self, future, Stream};
use hyper::rt::Future;
use hyper::service::{NewService, Service};
use hyper::{Body, Method, Request, Response};
use serde_json;

use capture::{CaptureWork, CaptureWorkType};
use shutdown;
use work::{
    AddClientRequest, AddClientResponse, RemoveClientRequest, RemoveClientResponse, WorkQueue,
    WorkReportRequest, WorkReportResponse, WorkRequest, WorkResponse,
};

pub struct WorkQueueService<'a, T, W> {
    /// Handles clients and work
    work_queue: Arc<Mutex<WorkQueue<T, W>>>,
    /// Writes Reports to a file
    report_sink: Arc<Mutex<BufWriter<File>>>,
    /// Channel future used to shutdown the server        
    shutdown: Arc<AtomicBool>,
    /// TODO: figure out why this exists
    _phantom: &'a PhantomData<()>,
}
/*impl<'a, T, W> NewService for WorkQueueService<'a, T, W>
where
    T: 'a + Eq + Clone + Hash + Send + DeserializeOwned + Serialize,
    W: 'a + Clone + Ord + Send + Serialize,
{*/
impl<'a> NewService for WorkQueueService<'a, CaptureWorkType, CaptureWork> {
    /// Type used to represent the request body
    type ReqBody = Body;
    /// Type used to represent the response body
    type ResBody = Body;
    /// Type of error to return when requests fail
    type Error = io::Error;

    /// Type of service to return
    type Service = Self;
    /// Type of error to return when service creation fails
    type InitError = io::Error;

    /// Type of Future to return
    type Future = Box<'a + Future<Item = Self::Service, Error = Self::InitError> + Send>;

    /// This creates a new service instance
    fn new_service(&self) -> Self::Future {
        Box::new(future::ok(Self {
            work_queue: self.work_queue.clone(),
            report_sink: self.report_sink.clone(),
            shutdown: self.shutdown.clone(),
            _phantom: &PhantomData,
        }))
    }
}

impl<'a> Service for WorkQueueService<'a, CaptureWorkType, CaptureWork> {
    /// Type used to represent the request body
    type ReqBody = Body;
    /// Type used to represent the response body
    type ResBody = Body;

    /// Type of error to return when requests fail
    type Error = io::Error;
    /// Type of Future to return
    type Future = Box<'a + Future<Item = Response<Body>, Error = Self::Error> + Send>;

    /// This handles requests to the server
    ///
    /// # Parameters
    /// * `request` - an HTTP request to the server
    fn call(&mut self, request: Request<Body>) -> Self::Future {
        // Log the request
        info!("{} {}", request.method(), request.uri().path());
        // Dispatch the request
        Box::new(
            match (request.method(), request.uri().path()) {
                (&Method::POST, "/client/add") => self.client_add(request),
                (&Method::POST, "/client/remove") => self.client_remove(request),
                (&Method::POST, "/work/get") => self.work_get(request),
                (&Method::POST, "/work/report") => self.work_report(request),
                _ => Box::new(future::ok(Response::new(Body::from("404")))),
            }
            .map_err(|err| {
                error!("Request error: {}", err);
                err
            }),
        )
    }
}

/*impl<'a, T, W> FromIterator<(T, W)> for WorkQueueService<'a, T, W>
where
    T: Eq + Clone + Hash + Send + DeserializeOwned + Serialize,
    W: Clone + Ord + Send + Serialize,
{
    /// Creates a work queue service from an iterator of work items
    ///
    /// # Parameters
    /// * `iter` - Iterator of (work type, work item)
    fn from_iter<I: IntoIterator<Item = (T, W)>>(iter: I) -> Self {
    }
}*/

impl<'a> WorkQueueService<'a, CaptureWorkType, CaptureWork> {
    /// Constructor
    pub fn new<I, P>(
        work_iter: I,
        output_path: P,
    ) -> Result<(Self, shutdown::ServerShutdown), io::Error>
    where
        I: IntoIterator<Item = (CaptureWorkType, CaptureWork)>,
        P: AsRef<Path>,
    {
        // Import work into a queue
        let work_queue = WorkQueue::from_iter(work_iter);
        // Open the given path
        let output_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)?;
        // Create a buffered writer on the file
        let report_sink = BufWriter::new(output_file);
        // Create shutdown future
        let shutdown_fut = shutdown::ServerShutdown::new();
        // Create the service
        Ok((
            WorkQueueService {
                work_queue: Arc::new(Mutex::new(work_queue)),
                report_sink: Arc::new(Mutex::new(report_sink)),
                shutdown: shutdown_fut.flag.clone(),
                _phantom: &PhantomData,
            },
            shutdown_fut,
        ))
    }
    /// Responds to a request to add a new client
    ///
    /// Assumes the request is a GET request
    /// # Parameters
    /// * `clients` - Client storage object used to handle client ids
    /// * `request` - HTTP request from the client
    fn client_add(&mut self, request: Request<Body>) -> <Self as Service>::Future {
        // Get a cloned reference to the work queue
        let work_queue = self.work_queue.clone();
        // Create a response
        let response_future = request
            // Extract body of the request
            .into_body()
            // Concatenate it all together
            .concat2()
            // Convert hyper errors to io::Error
            .map_err(as_io_error)
            // Parse the request body and request a client id
            .and_then(move |post_body|
                // Parse the request as JSON
                serde_json::from_slice(&post_body)
                    // Using the parsed request, register the client and obtain a client ID
                    // Convert errors to io::Error
                    .map_err(as_io_error))
            .and_then(move |request: AddClientRequest<CaptureWorkType>| {
                // Get a lock on the work queue
                let result = work_queue
                    .lock()
                    .map(|mut wq| wq.add_client(request.work_types))
                    .map_err(|_| as_io_error("t"));
                result
            })
            // Create a response body
            .and_then(|client_id: u64| {
                // Create the response object
                let response = AddClientResponse {
                    success: true,
                    client_id,
                    error: None,
                };
                // Serialize the response
                serde_json::to_string(&response)
                    // Convert serialization errors to io::Error
                    .map_err(as_io_error)
            })
            // Create a response object
            .and_then(|body: String| Ok(Response::new(Body::from(body))));
        // Box the future
        Box::new(response_future)
    }
    /// Responds to a request to remove a client
    ///
    /// Assumes the request is a GET request
    /// # Parameters
    /// * `work_queue` - WorkQueue that handles clients
    /// * `request` - HTTP request from the client
    fn client_remove(&mut self, request: Request<Body>) -> <Self as Service>::Future {
        // Get a cloned reference to the work queue
        let work_queue = self.work_queue.clone();
        let shutdown = self.shutdown.clone();
        // Create a response
        let response_future = request
            // Extract body of the request
            .into_body()
            // Concatenate it all together
            .concat2()
            // Convert hyper errors to io::Error
            .map_err(as_io_error)
            // Parse the request body
            .and_then(|post_body| {
                serde_json::from_slice(&post_body)
                    // Convert errors to io::Error
                    .map_err(as_io_error)
            })
            // Extract client ID and remove the client
            .and_then(move |request: RemoveClientRequest| {
                // Remove the client
                let response = work_queue
                    // Get mutex lock on client
                    .lock()
                    // Remove client ID from client
                    .map(|mut work_queue| {
                        work_queue.remove_client(request.client_id);
                        work_queue.num_clients()
                    })
                    // Convert error to io::Error
                    .map_err(|_| as_io_error("failed to acquire mutex"));
                response
            })
            // Serialize a response body
            .and_then(move |num_clients: usize| {
                // Send shutdown signal
                if num_clients == 0 {
                    shutdown.store(true, Ordering::SeqCst);
                }
                Ok(())
            })
            .and_then(|()| {
                // Create the response object
                let response = RemoveClientResponse {
                    success: true,
                    error: None,
                };
                // Serialize the response
                (serde_json::to_string(&response))
                    // Convert serialization errors to io::Error
                    .map_err(as_io_error)
            })
            // Create a response object
            .and_then(|body: String| Ok(Response::new(Body::from(body))));
        Box::new(response_future)
    }

    /// Responds to a request for work
    ///
    /// # Parameters
    /// * `work_queue` - Queue to request work from
    /// * `request` - request from the client
    fn work_get(&mut self, request: Request<Body>) -> <Self as Service>::Future {
        // Get a cloned reference to the work queue
        let work_queue = self.work_queue.clone();
        // Create a response
        let response_future = request
            // Extract body of the request
            .into_body()
            // Concatenate it all together
            .concat2()
            // Convert hyper errors to io::Error
            .map_err(as_io_error)
            // Parse the request body as JSON
            .and_then(|post_body| serde_json::from_slice(&post_body).map_err(as_io_error))
            // Get a lock on the work queue and request work
            .and_then(move |request: WorkRequest| {
                // Lock the work queue mutex
                let response = work_queue
                    .lock()
                    // Request work
                    .map(|mut work_queue| {
                        work_queue
                            .request_work(request.client_id)
                            .ok_or_else(|| as_io_error("Failed to request work"))
                    })
                    // Convert error to io::Error
                    .map_err(|_| as_io_error("failed to acquire mutex"));
                response
            })
            // Flatten the future
            .flatten()
            .and_then(|(work_type, work): (CaptureWorkType, CaptureWork)| {
                // Create the response object
                let response = WorkResponse {
                    success: true,
                    work_type,
                    work,
                    error: None,
                };
                // Serialize the response
                serde_json::to_string(&response)
                    // Convert serialization errors to io::Error
                    .map_err(as_io_error)
            })
            // Create a response object
            .and_then(|body: String| Ok(Response::new(Body::from(body))));
        // Return the response as a future
        Box::new(response_future)
    }
}
impl<'a> WorkQueueService<'a, CaptureWorkType, CaptureWork> {
    /// Handles a work report
    ///
    /// Assumes the request is a POST request
    /// # Parameters
    /// * `report_sink` - Sink to use for writing reports
    /// * `request` - incoming request
    fn work_report(&mut self, request: Request<Body>) -> <Self as Service>::Future {
        // Get a cloned reference to the report sink
        let report_sink = self.report_sink.clone();
        // Get a cloned reference to the work queue
        let work_queue = self.work_queue.clone();
        // Create a response
        let response_future = request
            // Extract body of the request
            .into_body()
            // Concatenate it all together
            .concat2()
            // Convert hyper errors to io::Error
            .map_err(as_io_error)
            // Parse the request body as JSON
            .and_then(|post_body| serde_json::from_slice(&post_body).map_err(as_io_error))
            // Get a lock on the work queue and request work
            .and_then(
                move |request: WorkReportRequest<CaptureWorkType, CaptureWork>| {
                    if request.success {
                        report_sink
                            // Get mutex lock on report sink
                            .lock()
                            // Report the given work report
                            .map(|mut report_sink| {
                                // Convert the report back into json
                                let report = serde_json::to_string(&request)?;
                                // Write the report to a file
                                writeln!(*report_sink, "{}", report)?;
                                // Flush to the file immediately
                                report_sink.flush()?;
                                // Return success if nothing failed
                                Ok(())
                            })
                            // Convert error to io::Error
                            .map_err(|_| as_io_error("failed to acquire mutex"))
                    } else {
                        work_queue
                            .lock()
                            .map(|mut work_queue| {
                                work_queue.add_work(request.work_type, request.work);
                                Ok(())
                            })
                            .map_err(|_| as_io_error("failed to acquire mutex"))
                    }
                },
            )
            .flatten()
            .and_then(|()| {
                // Create the response object
                let response = WorkReportResponse {
                    success: true,
                    error: None,
                };
                // Serialize the response
                serde_json::to_string(&response)
                    // Convert serialization errors to io::Error
                    .map_err(as_io_error)
            })
            // Create a response object
            .and_then(|body: String| Ok(Response::new(Body::from(body))));
        // Return the response as a future
        Box::new(response_future)
    }
}
/// Function to convert errors and strings to `io::Error`
///
/// # Parameters
/// * `error` - The error to convert to `io::Error`
fn as_io_error<E>(error: E) -> io::Error
where
    E: Into<Box<error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, error)
}
