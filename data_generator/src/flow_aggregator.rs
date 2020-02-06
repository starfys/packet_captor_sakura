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

use crate::bro_types::Connection;
use crate::packet::{Packet, StrippedPacket};
use itertools::Itertools;
use log::warn;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::IpAddr;

/// Associates packets with flows
pub struct FlowAggregator {
    /// The main data structure is a mapping of ID to a set of packets
    // TODO: Use something that strips the packet of fields contained in the packetkey
    data: HashMap<String, Vec<StrippedPacket>>,
    /// This is used to efficiently associate packets with flows
    connection_map: HashMap<PacketKey, Vec<FlowPeriod>>,
    /// Time (in ns) to allow a packet with a pre-flow timestamp tp be associated with a flow
    grace_period_before: u64,
    /// Time (in ns) to allow a packet with a post-flow timestamp tp be associated with a flow
    grace_period_after: u64,
}

impl FlowAggregator {
    /// Creates a new flow aggregator
    ///
    /// # Parameters
    /// * `connections` - Set of connections to associate future packets with
    /// * `grace_period_before` - Time (in ns) to allow a packet with a pre-flow timestamp to be
    ///                           associated with a flow
    /// * `grace_period_after` - Time (in ns) to allow a packet with a post-flow timestamp to be
    ///                          associated with a flow
    pub fn new(
        connections: impl Iterator<Item = Connection>,
        grace_period_before: u64,
        grace_period_after: u64,
    ) -> Self {
        // Create a mapping of packet identifiers to time periods
        let connection_map = connections
            .map(|connection| {
                // Get the identifier
                let key = PacketKey::from(&connection);
                // Get the time period and ID
                let period = FlowPeriod::from(&connection);
                // Return the key and time period
                (key, period)
            })
            .into_group_map();
        // TODO: determine if we care about connections that don't map to any packets

        FlowAggregator {
            data: HashMap::new(),
            connection_map,
            grace_period_before,
            grace_period_after,
        }
    }

    /// Loads packets into the aggregator
    ///
    /// # Parameters
    /// * `packets` - the packets to aggregate
    pub fn load_packets(&mut self, packets: Vec<Packet>) {
        // Represents the time relationship between the packet and the flow, if the packet did not
        // happen during the flow
        // The contained value is the absolute value of the time difference between the packet and
        // the flow
        #[derive(Copy, Clone, Eq, PartialEq, PartialOrd)]
        enum TimeDifference {
            After(u64),
            Before(u64),
        }
        impl Ord for TimeDifference {
            /// Compares two timedifferences
            fn cmp(&self, other: &TimeDifference) -> Ordering {
                use TimeDifference::*;
                match (self, other) {
                    // If the packet is after both flows, prefer the one it is closer to
                    (After(ref my_delta), After(ref their_delta)) => my_delta.cmp(&their_delta),
                    // If the packet is before both flows, prefer the one it is closer to
                    (Before(ref my_delta), Before(ref their_delta)) => my_delta.cmp(&their_delta),
                    // If the packet is after this flow and before the other, prefer this flow
                    (After(_), Before(_)) => Ordering::Less,
                    // If the packet is before this flow and after the other, prefer the other flow
                    (Before(_), After(_)) => Ordering::Greater,
                }
            }
        }
        // Used to keep track of potential flow matches
        struct FlowPossibility {
            // ID of the potential flow
            id: String,
            // Relationship between the packet's time and the flow period
            time_difference: Option<TimeDifference>,
        }
        // For each packet
        // TODO: parallelize this with par_iter
        // TODO: connection_map must be readable by many threads
        // TODO: mutex lock data
        for packet in packets {
            // Get identifiable information from the packet
            let key = PacketKey::from(&packet);
            // Search the connection list for connections with a matching identifier
            if let Some(periods) = self.connection_map.get(&key) {
                let flow_id = periods
                    .iter()
                    // Iterate over the possible periods. The result will either be a single
                    // possibility (Err is used for this, but it is not an error) or a set of
                    // possibilities. The single possibility implies that a perfect match was found,
                    // while a set of possibilities will be returned if a perfect match is not found
                    .try_fold(Vec::new(), |mut possibilities, period| {
                        // If the packet's time period matches perfectly
                        if packet.timestamp >= period.start && packet.timestamp <= period.end {
                            // Exit the iteration early with an "Error"
                            // TODO: create a type with a more accurate name
                            Err(FlowPossibility {
                                id: period.id.clone(),
                                time_difference: None,
                            })
                        }
                        // If the packet occured after the time period (within the grace period)
                        else if packet.timestamp < period.end + self.grace_period_after {
                            possibilities.push(FlowPossibility {
                                id: period.id.clone(),
                                time_difference: Some(TimeDifference::After(
                                    (period.end + self.grace_period_after) - packet.timestamp,
                                )),
                            });
                            Ok(possibilities)
                        }
                        // If the packet occured before the period (within the grace period)
                        else if packet.timestamp + self.grace_period_before > period.start {
                            possibilities.push(FlowPossibility {
                                id: period.id.clone(),
                                time_difference: Some(TimeDifference::Before(
                                    (packet.timestamp + self.grace_period_before) - period.start,
                                )),
                            });
                            Ok(possibilities)
                        } else {
                            Ok(possibilities)
                        }
                    })
                    // This function is only run in the case that a set of possibilities occurs
                    .map(|mut possibilities: Vec<FlowPossibility>| {
                        // Sort the possibilities
                        // This sort should put more suitable possibilities first in the array
                        possibilities
                            .sort_unstable_by_key(|possibility| possibility.time_difference);
                        // Get the first result
                        // If the set is empty, this will be None
                        possibilities
                            .first()
                            .map(|possibility| possibility.id.clone())
                    })
                    // This function is run if the iteration short-circuited and we got a perfect
                    // match. All we do here is extract the ID and map it to Option<String> to
                    // have the same type as we get when we have to check possibilities
                    .unwrap_or_else(|possibility: FlowPossibility| Some(possibility.id));

                if let Some(flow_id) = flow_id {
                    // Insert it
                    self.data
                        .entry(flow_id)
                        .or_insert_with(|| vec![])
                        .push(packet.strip());
                } else {
                    warn!(
                        "Failed to find a connection that matches the timestamp of: {:?}",
                        packet
                    );
                }
            } else {
                warn!("Failed to find a connection that maps the identifying information of packet: {:?}", packet);
            }
        }
        // Sort packets
        for (_, packets) in &mut self.data {
            packets.sort_unstable_by_key(|packet| packet.timestamp)
        }
    }
    /// Consumes the aggregator and returns aggregated flows
    pub fn into_aggregated_flows(self) -> HashMap<String, Vec<StrippedPacket>> {
        self.data
    }
}

/// Identifies a packet. This serves as a primary key capable of associating a packet with a flow
///
/// Timestamp is not included, and is determined later
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct PacketKey {
    ip_a: IpAddr,
    ip_b: IpAddr,
    trans_protocol: u8,
    port_a: u16,
    port_b: u16,
}

impl PacketKey {
    /// Creates an identification key for a packet or flow
    ///
    /// IP and port will be ordered based on port. The ip/port pair with the lower port will be
    /// assigned to ip_a, port_a, while the ip/pair port with the higher port will be assigned to
    /// ip_b, port_b. If they are equal, variables will match the arguments
    pub fn new(ip_a: IpAddr, ip_b: IpAddr, trans_protocol: u8, port_a: u16, port_b: u16) -> Self {
        // Order the IP and port
        let (ip_a, ip_b, port_a, port_b) = if port_a <= port_b {
            (ip_a, ip_b, port_a, port_b)
        } else {
            (ip_b, ip_a, port_b, port_a)
        };
        // Create the object
        PacketKey {
            ip_a,
            ip_b,
            trans_protocol,
            port_a,
            port_b,
        }
    }
}

impl<'a> From<&'a Packet> for PacketKey {
    /// Extracts key identifying features from a packet
    fn from(packet: &'a Packet) -> Self {
        PacketKey::new(
            packet.src_ip,
            packet.dst_ip,
            packet.trans_protocol,
            packet.src_port,
            packet.dst_port,
        )
    }
}
impl<'a> From<&'a Connection> for PacketKey {
    /// Extracts key identifying features from a connection
    fn from(connection: &'a Connection) -> Self {
        PacketKey::new(
            connection.orig_ip,
            connection.resp_ip,
            connection.trans_protocol.code(),
            connection.orig_port,
            connection.resp_port,
        )
    }
}

/// Identifies the time during which a flow took place, and the flow's UID
///
/// Allows associating a `PacketKey` with a flow
#[derive(Clone)]
struct FlowPeriod {
    start: u64,
    end: u64,
    pub id: String,
}

impl<'a> From<&'a Connection> for FlowPeriod {
    /// Extracts key identifying features from a connection
    fn from(connection: &'a Connection) -> Self {
        FlowPeriod {
            start: connection.timestamp,
            end: connection.timestamp + connection.duration,
            id: connection.uid.clone(),
        }
    }
}
