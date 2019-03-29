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
extern crate byteorder;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate nix;

mod error;

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};

use byteorder::{LittleEndian, ReadBytesExt};
use nix::errno::Errno;
use nix::sys::signal;
use nix::unistd::Pid;

use error::TcpdumpError;

fn terminate_child(mut child: Child) -> Result<(), TcpdumpError> {
    // Get pid as proper type
    let pid = Pid::from_raw(child.id() as i32);
    // Send sigterm to child and check for errors
    if let Err(term_err) = signal::kill(pid, signal::Signal::SIGTERM) {
        // Don't try to send a SIGKILL if the SIGTERM failed due to the process already being dead
        if term_err != nix::Error::Sys(Errno::ESRCH) {
            // If sending SIGTERM fails, use the native interface that sends a SIGKILL
            // Check whether this fails
            if let Err(kill_err) = child.kill() {
                if kill_err.kind() != io::ErrorKind::InvalidInput {
                    return Err(TcpdumpError::KillError(term_err, kill_err));
                }
            }
            // Return and encapsulate the error
            return Err(TcpdumpError::SigtermError(term_err));
        }
    }
    // Wait for child to die
    child
        .wait()
        // Convert wait error
        .map_err(TcpdumpError::WaitError)
        // If waiting succeeds, check exit status of program
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(TcpdumpError::ChildExitError(status))
            }
        })
}
fn handle_connection(
    mut stream: &mut UnixStream,
    mut tcpdump: Option<Child>,
) -> Result<Option<Child>, TcpdumpError> {
    // All requests are bytes, allocate 1 byte
    let mut request: [u8; 1] = [0];
    // Get command code
    while let Ok(_) = stream.read(&mut request) {
        // Execute the command
        let command_result = handle_command(request[0], &mut stream, tcpdump);
        // Determine the return code
        let return_code = if command_result.is_ok() { 0x00 } else { 0x01 };
        // Send the return code
        if let Err(err) = stream.write(&[return_code]) {
            if let Ok(Some(child)) = command_result {
                terminate_child(child)?;
            }
            return Err(TcpdumpError::SocketIOError(err));
        }
        // Flush the output stream
        if let Err(err) = stream.flush() {
            if let Ok(Some(child)) = command_result {
                terminate_child(child)?;
            }
            return Err(TcpdumpError::SocketIOError(err));
        }
        // Handle the command's output
        match command_result {
            // If the command succeeded, and returned, then accept the child
            Ok(new_tcpdump) => {
                tcpdump = new_tcpdump;
            }
            // If the command failed with an error, terminate the connection and return the error
            Err(err) => return Err(err),
        }
    }
    Ok(tcpdump)
}

fn handle_command(
    command: u8,
    stream: &mut UnixStream,
    tcpdump: Option<Child>,
) -> Result<Option<Child>, TcpdumpError> {
    let tcpdump = match command {
        // Start tcpdump
        0x00 => {
            // Read in the TCPDUMP Start parameters
            // Read the length of the filename
            // If we can't read command arguments, then the connection is in an
            // undetermined state, and tcpdump should be shut down just in case
            let mut filename_length = match stream.read_u32::<LittleEndian>() {
                Ok(filename_length) => filename_length,
                Err(err) => {
                    // Shut down tcpdump if it exists
                    if let Some(child) = tcpdump {
                        terminate_child(child)?;
                    }
                    // Return the error
                    return Err(TcpdumpError::SocketIOError(err));
                }
            };
            // Ensure it's not allocating some insane amount
            const MAX_FILENAME_LENGTH: u32 = 1024 * 1024;
            // Return error
            if filename_length > MAX_FILENAME_LENGTH {
                // Shut down tcpdump if it exists
                if let Some(child) = tcpdump {
                    terminate_child(child)?;
                }
                return Err(TcpdumpError::FilenameLengthError);
            }
            // Create a buffer for the filename
            let mut filename_buffer = vec![0; filename_length as usize];
            // Read the filename
            // If we can't read command arguments, then the connection is in an
            // undetermined state, and tcpdump should be shut down just in case
            match stream.read(&mut filename_buffer) {
                Ok(_) => {}
                Err(err) => {
                    // Shut down tcpdump if it exists
                    if let Some(child) = tcpdump {
                        terminate_child(child)?;
                    }
                    // Return the error
                    return Err(TcpdumpError::SocketIOError(err));
                }
            }
            // Convert filename to string
            // This error is non-fatal. It will be returned to the client
            let filename = match String::from_utf8(filename_buffer) {
                Ok(filename) => filename,
                Err(err) => {
                    // Shut down tcpdump if it exists
                    if let Some(child) = tcpdump {
                        terminate_child(child)?;
                    }
                    return Err(TcpdumpError::FilenameParseError(err));
                }
            };

            // Check if there is already a tcpdump started
            // Non-fatal, returned to client
            if tcpdump.is_some() {
                if let Some(child) = tcpdump {
                    terminate_child(child)?;
                }
                return Err(TcpdumpError::ExistingTcpdumpError);
            }

            // Start tcpdump
            // Error here is fatal
            let mut child = Command::new("tcpdump")
                .args(&["-j", "host_hiprec", "-K", "-w", &filename])
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(TcpdumpError::SpawnError)?;

            // Remove the child's stderr handle
            let stderr = match child.stderr.take() {
                Some(stderr) => stderr,
                None => {
                    // If there is not stderr, terminate the child
                    terminate_child(child)?;
                    // Return with an error
                    return Err(TcpdumpError::StderrError);
                }
            };

            // Read a line from the child's stderr
            info!("Waiting for tcpdump to print initial startup message");
            // Get buffered reader to read until newline
            let mut stderr_reader = BufReader::new(stderr);
            // Allocate buffer to store the line
            let mut first_line = String::new();
            // Read the first line
            match stderr_reader.read_line(&mut first_line) {
                Ok(_) => {
                    info!("Tcpdump printed first line: {}", first_line);
                }
                Err(err) => {
                    // If the process terminates and stderr ends, tcpdump has failed.
                    // Terminate the process
                    terminate_child(child)?;
                    // Return an error
                    return Err(TcpdumpError::InitialMessageError(err));
                }
            }
            // Retrieve stderr out of the bufreader, so we can return it to the child object
            // This discards any buffered input, but we don't care about that
            let stderr = stderr_reader.into_inner();
            // Put stderr back into the child so it isn't deallocated here
            child.stderr = Some(stderr);
            // Pass the child back up to the connection handler, and indicate that we will not
            // shutdown
            Some(child)
        }
        // Stop tcpdump
        0x01 => {
            if let Some(child) = tcpdump {
                // Terminate the child
                terminate_child(child)?;
                info!("Stopped tcpdump");
            } else {
                return Err(TcpdumpError::NonexistingTcpdumpError);
            }
            // The child is now non-existent
            None
        }
        // Shut down the whole thing
        0x02 => {
            if let Some(child) = tcpdump {
                info!("Stopping tcpdump");
                terminate_child(child)?;
                info!("Stopped tcpdump");
            }
            return Err(TcpdumpError::ShutdownError);
        }
        // Invalid command
        invalid_command => {
            // We could fail here, but we only pass through the child on success,
            // so we'll log a warning and let this slide
            warn!("Received invalid command {:x}", invalid_command);
            tcpdump
        }
    };
    Ok(tcpdump)
}

fn main() -> Result<(), TcpdumpError> {
    // Set up logger
    env_logger::init();

    // Set filename for socket
    const SOCKET_FILENAME: &'static str = "/tmp/tcpdump.socket";

    // Remove the socket file if it exists
    debug!("Removing old socket file");
    if let Err(err) = fs::remove_file(SOCKET_FILENAME) {
        // Ignore not found error
        if err.kind() == io::ErrorKind::NotFound {
            info!("Socket file does not exist, ignoring");
        } else {
            return Err(TcpdumpError::RemoveSocketError(err));
        }
    }

    // Listen on a unix socket
    info!("Creating socket");
    let listener = UnixListener::bind(SOCKET_FILENAME).expect("Failed to listen on unix socket");

    // Set permissions on the socket to allow anyone to write to it
    info!("Setting permissions on socket file");
    let mut permissions = fs::metadata(SOCKET_FILENAME)
        .map_err(TcpdumpError::SocketMetadataError)?
        .permissions();
    permissions.set_mode(0o662);
    fs::set_permissions(SOCKET_FILENAME, permissions).map_err(TcpdumpError::SocketMetadataError)?;

    // Manage a single process
    let mut tcpdump: Option<Child> = None;

    // Handle connections to the unix socket
    info!("Listening on {}", SOCKET_FILENAME);
    for connection in listener.incoming() {
        info!("New connection on socket");
        // Ensure the connection worked
        match connection {
            Ok(mut connection) => {
                // Store child after connection
                tcpdump = match handle_connection(&mut connection, tcpdump) {
                    Ok(tcpdump) => tcpdump,
                    Err(err) => {
                        error!("{}", err);
                        break;
                    }
                }
            }
            Err(err) => {
                error!("Connection error: {}", err);
                continue;
            }
        }
    }
    Ok(())
}
