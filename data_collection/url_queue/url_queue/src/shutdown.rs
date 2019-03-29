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
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::{Async, Future, Poll};

pub struct ServerShutdown {
    pub flag: Arc<AtomicBool>,
}
impl ServerShutdown {
    pub fn new() -> Self {
        ServerShutdown {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Future for ServerShutdown {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Check the flag
        if self.flag.load(Ordering::SeqCst) {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }
}
