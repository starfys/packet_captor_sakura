// Copyright 2018 Steven Sheffey
// This file is part of tcpdump_controller.
//
// tcpdump_controller is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// tcpdump_controller is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with tcpdump_controller.  If not, see <http://www.gnu.org/licenses/>.
use std::fmt;
use std::io;
use std::process::ExitStatus;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum TcpdumpError {
    // Socket file management
    /// Error deleting socket
    RemoveSocketError(io::Error),
    /// Error getting or setting socket metadata
    SocketMetadataError(io::Error),

    // Communication
    /// Error communicating over unix socket
    SocketIOError(io::Error),

    // Starting TCPDUMP
    /// Given filename size is too long
    FilenameLengthError,
    /// Failed to parse filename
    FilenameParseError(FromUtf8Error),
    /// TCPDUMP is already started
    ExistingTcpdumpError,
    /// Error starting TCPDUMP
    SpawnError(io::Error),
    /// Error getting stderr handle
    StderrError,
    /// Error reading first line of stderr
    InitialMessageError(io::Error),

    // Killing TCPDUMP
    /// Error killing child with SIGTERM
    SigtermError(nix::Error),
    /// Error killing child with both SIGTERM and SIGKILL
    KillError(nix::Error, io::Error),
    /// Error waiting for child to die
    WaitError(io::Error),
    /// Child exited with failure status
    ChildExitError(ExitStatus),

    // Stopping TCPDUMP
    /// Received stop command but no tcpdump process exists
    NonexistingTcpdumpError,

    // Shuttting down
    /// Error that indicates the server should shut donw
    ShutdownError,
}

impl fmt::Display for TcpdumpError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use TcpdumpError::*;
        write!(
            formatter,
            "{}",
            match *self {
                RemoveSocketError(ref err) => format!("Error removing socket file: {}", err),
                SocketMetadataError(ref err) => format!("Error accessing metadata: {}", err),
                SocketIOError(ref err) => format!("Error communicating on socket: {}", err),
                FilenameLengthError => "Error: Given filename length is too long".to_string(),
                FilenameParseError(ref err) => format!("Error parsing filename: {}", err),
                ExistingTcpdumpError => {
                    "Error starting TCPDUMP: TCPDUMP is already started".to_string()
                }
                SpawnError(ref err) => format!("Error spawning TCPDUMP: {}", err),
                StderrError => "Error reading TCPDUMP's stderr: stderr does not exist".to_string(),
                InitialMessageError(ref err) => format!("Error reading TCPDUMP's stderr: {}", err),
                SigtermError(ref err) => format!("Error terminating TCPDUMP: {}", err),
                KillError(ref term_error, ref kill_error) => format!(
                    "Error terminating child: {}. Additionally, error killing child: {}",
                    term_error, kill_error
                ),
                WaitError(ref err) => format!("Error waiting for child to die: {}", err),
                ChildExitError(ref status) => {
                    format!("Child exited with failure status code: {}", status)
                }
                NonexistingTcpdumpError => {
                    "Error attempting to stop TCPDUMP: TCPDUMP is not started".to_string()
                }
                ShutdownError => "Shutting down".to_string(),
            }
        )
    }
}

impl std::error::Error for TcpdumpError {}
