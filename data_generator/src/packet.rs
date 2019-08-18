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
use failure::Error;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::FromPacket;

use std::net::IpAddr;
use std::path::Path;

use crate::entropy::*;
use crate::pcap::*;

#[derive(Debug)]
/// Basic features extracted from a PCAP record
pub struct Packet {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Transport protocol
    pub trans_protocol: u8,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Length of the application layer payload
    pub payload_length: usize,
    /// Entropy of the application layer payload
    pub entropy: f64,
    /// Timestamp for the packet's occurrence
    pub timestamp: u64,
}

#[derive(Debug, Fail)]
pub enum ParsePacketError {
    #[fail(display = "Failed to parse ethernet header")]
    InvalidEthernetHeader,
    #[fail(display = "Failed to parse IPV4 header")]
    InvalidIpv4Header,
    #[fail(display = "Failed to parse IPV6 header")]
    InvalidIpv6Header,
    #[fail(display = "Unsupported ethertype")]
    InvalidInternetLayer,
    #[fail(display = "Failed to parse TCP header")]
    InvalidTcpHeader,
    #[fail(display = "Failed to parse UDP header")]
    InvalidUdpHeader,
    #[fail(display = "Unsupported transport protocol")]
    InvalidTransportProtocol,
}

impl Packet {
    pub fn load_from_pcap(pcap_path: &Path) -> Result<impl Iterator<Item = Self>, Error> {
        // Open the pcap file
        let pcap_reader = PcapReader::open(pcap_path).expect("Failed to initialize Pcap reader");
        // Extract whether the pcap is nanosecond resolution
        let is_nanosecond_res: bool = pcap_reader.is_nanosecond_res;
        // Iterate over the pcap records
        let packets =
            pcap_reader.flat_map(move |record| Self::from_record(record, is_nanosecond_res));
        Ok(packets)
    }

    pub fn from_record(
        record: PcapRecord,
        is_nanosecond_res: bool,
    ) -> Result<Self, ParsePacketError> {
        // Parse out the ethernet header
        let ethernet_header = match EthernetPacket::owned(record.data) {
            Some(ethernet_header) => ethernet_header.from_packet(),
            None => return Err(ParsePacketError::InvalidEthernetHeader),
        };
        // Parse out the IP header
        let (src_ip, dst_ip, payload, trans_protocol) = match ethernet_header.ethertype {
            EtherTypes::Ipv4 => match Ipv4Packet::owned(ethernet_header.payload) {
                Some(ipv4_header) => {
                    // Extract the header
                    let ipv4_header = ipv4_header.from_packet();
                    // Extract fields
                    (
                        IpAddr::V4(ipv4_header.source),
                        IpAddr::V4(ipv4_header.destination),
                        ipv4_header.payload,
                        ipv4_header.next_level_protocol,
                    )
                }
                None => return Err(ParsePacketError::InvalidIpv4Header),
            },
            EtherTypes::Ipv6 => match Ipv6Packet::owned(ethernet_header.payload) {
                Some(ipv6_header) => {
                    // Extract the header
                    let ipv6_header = ipv6_header.from_packet();
                    // Extract fields
                    (
                        IpAddr::V6(ipv6_header.source),
                        IpAddr::V6(ipv6_header.destination),
                        ipv6_header.payload,
                        ipv6_header.next_header,
                    )
                }
                None => return Err(ParsePacketError::InvalidIpv6Header),
            },
            _ => return Err(ParsePacketError::InvalidInternetLayer),
        };
        // Parse out the TCP header
        let (src_port, dst_port, payload) = match trans_protocol {
            IpNextHeaderProtocols::Tcp => match TcpPacket::owned(payload) {
                Some(tcp_header) => {
                    // Extract the TCP header
                    let tcp_header = tcp_header.from_packet();
                    // Extract fields from the TCP header
                    (
                        tcp_header.source,
                        tcp_header.destination,
                        tcp_header.payload,
                    )
                }
                None => return Err(ParsePacketError::InvalidTcpHeader),
            },
            IpNextHeaderProtocols::Udp => match UdpPacket::owned(payload) {
                Some(udp_header) => {
                    // Extract the TCP header
                    let udp_header = udp_header.from_packet();
                    // Extract fields from the TCP header
                    (
                        udp_header.source,
                        udp_header.destination,
                        udp_header.payload,
                    )
                }
                None => return Err(ParsePacketError::InvalidUdpHeader),
            },
            _ => return Err(ParsePacketError::InvalidTransportProtocol),
        };
        // Construct a packet from useful features
        Ok(Packet {
            src_ip,
            dst_ip,
            trans_protocol: trans_protocol.0,
            src_port,
            dst_port,
            payload_length: payload.len(),
            entropy: payload.shannon_entropy(),
            timestamp: record.header.get_time_as_nanos(is_nanosecond_res),
        })
    }

    /// Strip out features that are identifying and not useful for generating features
    pub fn strip(self) -> StrippedPacket {
        StrippedPacket::from(self)
    }
}

/// A packet stripped of identifying features, leaving only those useful for
/// feature generation
pub struct StrippedPacket {
    /// Transport protocol
    pub trans_protocol: u8,
    /// Length of the application layer payload
    pub payload_length: usize,
    /// Entropy of the application layer payload
    pub entropy: f64,
    /// Timestamp for the packet's occurrence
    pub timestamp: u64,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
}

impl From<Packet> for StrippedPacket {
    /// Converts a packet into a stripped packet
    fn from(packet: Packet) -> Self {
        StrippedPacket {
            trans_protocol: packet.trans_protocol,
            payload_length: packet.payload_length,
            entropy: packet.entropy,
            timestamp: packet.timestamp,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
        }
    }
}
