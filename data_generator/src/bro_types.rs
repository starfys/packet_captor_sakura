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
use failure;
use pnet_packet::ip::IpNextHeaderProtocols::{Icmp, Tcp, Udp};
use serde::{Deserialize, Deserializer};
use serde_derive::Deserialize;
use serde_json;

use std::convert::From;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

/// Connection state for a flow
#[derive(Debug, Deserialize)]
pub enum ConnState {
    /// Connection attempt seen, no reply.
    S0,
    /// Connection established, not terminated.
    S1,
    /// Normal establishment and termination. Note
    /// that this is the same symbol as for state S1.
    /// You can tell the two apart because for S1 there
    /// will not be any byte counts in the summary, while
    /// for SF there will be.
    SF,
    /// Connection attempt rejected.
    REJ,
    /// Connection established and close attempt by originator
    /// seen (but no reply from responder).
    S2,
    /// Connection established and close attempt by responder seen
    /// (but no reply from originator).
    S3,
    /// Connection established, originator aborted (sent a RST).
    RSTO,
    /// Responder sent a RST.
    RSTR,
    /// Originator sent a SYN followed by a RST, we never saw a
    /// SYN-ACK from the responder.
    RSTOS0,
    /// Responder sent a SYN ACK followed by a RST, we never saw
    /// a SYN from the (purported) originator.
    RSTRH,
    /// Originator sent a SYN followed by a FIN, we never saw a
    /// SYN ACK from the responder (hence the connection was “half” open).
    SH,
    /// Responder sent a SYN ACK followed by a FIN, we never saw
    /// a SYN from the originator.
    SHR,
    /// No SYN seen, just midstream traffic (a “partial connection”
    /// that was not later closed).
    OTH,
    /// Unknown. used as a default
    UNK,
}

impl Default for ConnState {
    /// Returns a default state
    fn default() -> Self {
        ConnState::UNK
    }
}

/// History entry for connection state
#[derive(Debug, PartialEq)]
pub enum HistoryEntry {
    /// s 	a SYN w/o the ACK bit set
    Syn,
    /// h 	a SYN+ACK (“handshake”)
    Handshake,
    /// a 	a pure ACK
    Ack,
    /// d 	packet with payload (“data”)
    Data,
    /// f 	packet with FIN bit set
    Fin,
    /// r 	packet with RST bit set
    Rst,
    /// c 	packet with a bad checksum
    BadChecksum,
    /// t 	packet with retransmitted payload
    Retransmit,
    /// i 	inconsistent packet (e.g. FIN+RST bits set)
    Inconsistent,
    /// q 	multi-flag packet (SYN+FIN or SYN+RST bits set)
    MultiFlag,
    /// ^ 	connection direction was flipped by Bro’s heuristic
    DirectionFlipped,
    // Used so we have something to use for invalid input
    Unknown,
}
impl From<char> for HistoryEntry {
    /// Parses a char into a HistoryEntry
    fn from(c: char) -> Self {
        match c {
            's' => HistoryEntry::Syn,
            'h' => HistoryEntry::Handshake,
            'a' => HistoryEntry::Ack,
            'd' => HistoryEntry::Data,
            'f' => HistoryEntry::Fin,
            'r' => HistoryEntry::Rst,
            'c' => HistoryEntry::BadChecksum,
            't' => HistoryEntry::Retransmit,
            'i' => HistoryEntry::Inconsistent,
            'q' => HistoryEntry::MultiFlag,
            '^' => HistoryEntry::DirectionFlipped,
            _ => HistoryEntry::Unknown,
        }
    }
}

/// Represents a transport protocol, as supported by Bro
#[derive(Debug, Deserialize)]
pub enum TransportProtocol {
    /// An unknown transport-layer protocol.
    #[serde(rename = "unknown_transport")]
    Unknown,
    /// TCP
    #[serde(rename = "tcp")]
    Tcp,
    /// UDP
    #[serde(rename = "udp")]
    Udp,
    /// ICMP
    #[serde(rename = "icmp")]
    Icmp,
}

impl TransportProtocol {
    /// Returns the IP nextProtocol code for a transport protocol
    pub fn code(&self) -> u8 {
        match *self {
            TransportProtocol::Unknown => 0x00,
            TransportProtocol::Tcp => Tcp.0,
            TransportProtocol::Udp => Udp.0,
            TransportProtocol::Icmp => Icmp.0,
        }
    }
}

/// Used to deserialize a floating-point timestamp (in seconds) as an integer timestamp (in
/// nanoseconds)
pub fn parse_bro_timestamp<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    // Get the time as a float in seconds
    // Multiply by 1M to convert to microseconds
    // This is the default accuracy of bro
    let microseconds = f64::deserialize(deserializer)? * 1e6;
    // Convert into an integer, and multiply to get nanoseconds
    Ok((microseconds as u64) * 1000)
}
#[derive(Debug, Deserialize)]
pub struct Connection {
    #[serde(rename = "ts")]
    #[serde(deserialize_with = "parse_bro_timestamp")]
    pub timestamp: u64,
    pub uid: String,
    #[serde(rename = "id.orig_h")]
    pub orig_ip: IpAddr,
    #[serde(rename = "id.resp_h")]
    pub resp_ip: IpAddr,
    #[serde(rename = "id.orig_p")]
    pub orig_port: u16,
    #[serde(rename = "id.resp_p")]
    pub resp_port: u16,
    #[serde(rename = "proto")]
    pub trans_protocol: TransportProtocol,
    pub service: Option<String>,
    #[serde(deserialize_with = "parse_bro_timestamp")]
    #[serde(default)]
    pub duration: u64,
    pub orig_bytes: Option<i64>,
    pub resp_bytes: Option<i64>,
    pub conn_state: Option<ConnState>,
    pub missed_bytes: Option<i64>,
    #[serde(default)]
    pub history: String,
    pub orig_pkts: Option<i64>,
    pub orig_ip_bytes: Option<i64>,
    pub resp_pkts: Option<i64>,
    pub resp_ip_bytes: Option<i64>,
}
impl Connection {
    pub fn load_connections(
        path: &Path,
    ) -> Result<impl Iterator<Item = Connection>, failure::Error> {
        // Open the connection log
        let conn_log_file: File = File::open(path)?;
        let conn_log_reader = BufReader::new(conn_log_file);
        // Parse each line
        let connections = conn_log_reader.lines().flatten().flat_map(|line| {
            // Parse the line as json
            serde_json::from_str(&line)
        });
        Ok(connections)
    }
}
