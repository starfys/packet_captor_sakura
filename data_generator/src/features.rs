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
use std::collections::HashSet;
use std::ops;

use crate::packet::*;

/// Per-packet features
#[derive(Clone, Debug)]
pub struct PacketFeatures {
    /// Length of the application-layer payload
    pub payload_length: usize,
    /// Time since last packet of this direction
    interarrival_time: u64,
    /// Direction
    pub direction: PacketDirection,
}

/// Per-packet features
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketDirection {
    FromClient,
    ToClient,
    Unknown,
}
impl Into<f64> for PacketDirection {
    fn into(self) -> f64 {
        use PacketDirection::*;
        match self {
            FromClient => 0.0,
            ToClient => 1.0,
            Unknown => 0.5,
        }
    }
}

/// Packet direction inference method
#[derive(PartialEq)]
pub enum DirectionInferenceMethod {
    Ephemeral,
    ServerPort(u16),
    ServerPorts(HashSet<u16>),
}
impl DirectionInferenceMethod {
    /// Minimum ephemeral port according to IANA standards
    pub const MIN_IANA_EPH_PORT: u16 = 49152;
    /// Maximum ephemeral port according to IANA standards
    pub const MAX_IANA_EPH_PORT: u16 = 65535;
    /// Minimum ephemeral port used frequently by the Linux kernel
    pub const MIN_LINUX_EPH_PORT: u16 = 32768;
    /// Maximum ephemeral port used frequently by the Linux kernel
    pub const MAX_LINUX_EPH_PORT: u16 = 61000;

    /// Infers the direction of a packet using many methods
    pub fn infer_multiple(src_port: u16, dst_port: u16, methods: &[Self]) -> PacketDirection {
        use DirectionInferenceMethod::*;
        let last_ephemeral: Option<Option<PacketDirection>> = None;
        methods
            .iter()
            .scan(last_ephemeral, |last_ephemeral, method| {
                // If method is ephemeral
                if *method == Ephemeral {
                    // If ephemeral check has been run
                    if let Some(last_ephemeral) = last_ephemeral {
                        // Return cached value
                        last_ephemeral.clone()
                    } else {
                        let dir = method.infer(src_port, dst_port);
                        *last_ephemeral = Some(dir.clone());
                        dir
                    }
                } else {
                    method.infer(src_port, dst_port)
                }
            })
            .next()
            .unwrap_or_else(|| PacketDirection::Unknown)
    }
    /// Infers the direction of a packet using our chosen method
    pub fn infer(&self, src_port: u16, dst_port: u16) -> Option<PacketDirection> {
        use DirectionInferenceMethod::*;
        match *self {
            Ephemeral => Self::infer_ephemeral(src_port, dst_port),
            ServerPort(server_port) => {
                Self::infer_from_server_port(src_port, dst_port, server_port)
            }
            ServerPorts(ref server_ports) => {
                Self::infer_from_server_ports(src_port, dst_port, &server_ports)
            }
        }
    }

    /// Infers packet direction when some set of server ports is known
    /// If this inference fails, return None
    fn infer_from_server_port(
        src_port: u16,
        dst_port: u16,
        server_port: u16,
    ) -> Option<PacketDirection> {
        use PacketDirection::*;
        if dst_port == server_port {
            Some(FromClient)
        } else if src_port == server_port {
            Some(ToClient)
        } else {
            None
        }
    }

    /// Infers packet direction when some set of server ports is known
    /// If this inference fails, return None
    fn infer_from_server_ports(
        src_port: u16,
        dst_port: u16,
        server_ports: &HashSet<u16>,
    ) -> Option<PacketDirection> {
        use PacketDirection::*;
        if server_ports.contains(&dst_port) {
            Some(FromClient)
        } else if server_ports.contains(&src_port) {
            Some(ToClient)
        } else {
            None
        }
    }

    /// Infers packet direction based on whether a port seems to be ephemeral
    /// On linux systems, ephemeral ports are usually >= 32768
    /// If this inference fails, return None
    fn infer_ephemeral(src_port: u16, dst_port: u16) -> Option<PacketDirection> {
        use PacketDirection::*;
        // Check using the IANA standard first
        if src_port >= Self::MIN_IANA_EPH_PORT && src_port <= Self::MAX_IANA_EPH_PORT {
            Some(FromClient)
        } else if dst_port >= Self::MIN_IANA_EPH_PORT && dst_port <= Self::MAX_IANA_EPH_PORT {
            Some(ToClient)
        }
        // Check using common linux config
        else if src_port >= Self::MIN_LINUX_EPH_PORT && src_port <= Self::MAX_LINUX_EPH_PORT {
            Some(FromClient)
        } else if dst_port >= Self::MIN_LINUX_EPH_PORT && dst_port <= Self::MAX_LINUX_EPH_PORT {
            Some(ToClient)
        }
        // If none of the heuristics worked, we don't know
        else {
            None
        }
    }
}

impl PacketFeatures {
    /// Creates a set of packet features from packets
    pub fn from_stripped_packets(
        packets: Vec<StrippedPacket>,
        dir_inference_methods: &[DirectionInferenceMethod],
    ) -> Vec<Self> {
        // Keep track of the timestamp of the last packet in each direction
        struct LastTimestamps {
            from_client: Option<u64>,
            to_client: Option<u64>,
        }
        // Iterate over the packets
        packets
            .into_iter()
            .scan(
                LastTimestamps {
                    from_client: None,
                    to_client: None,
                },
                |lts, packet| {
                    // Determine the packet's direction
                    let direction = DirectionInferenceMethod::infer_multiple(
                        packet.src_port,
                        packet.dst_port,
                        dir_inference_methods,
                    );
                    // Get interarrival time
                    use PacketDirection::*;
                    let interarrival_time = match direction {
                        FromClient => {
                            // Calculate interarrival time
                            let iat = lts
                                .from_client
                                .map(|lfc| packet.timestamp - lfc)
                                .unwrap_or_else(|| 0);
                            // Set the new last_from_client time
                            lts.from_client = Some(packet.timestamp);
                            // Return interarrival time
                            iat
                        }
                        ToClient => {
                            // Calculate interarrival time
                            let iat = lts
                                .to_client
                                .map(|lfc| packet.timestamp - lfc)
                                .unwrap_or_else(|| 0);
                            // Set the new last_to_client time
                            lts.to_client = Some(packet.timestamp);
                            // Return interarrival time
                            iat
                        }
                        Unknown => 0,
                    };
                    // Return the feature set
                    Some(PacketFeatures {
                        payload_length: packet.payload_length,
                        interarrival_time,
                        direction,
                    })
                },
            )
            .collect()
    }
}

impl Into<[f64; 3]> for PacketFeatures {
    /// Converts packet features into a tensor
    fn into(self) -> [f64; 3] {
        [
            self.payload_length as f64,
            self.interarrival_time as f64,
            self.direction.into(),
        ]
    }
}

/// Overall flow features, extracted from packet-level features
#[derive(Debug)]
pub struct FlowFeatures {
    /// Frequency of packet sizes for this flow, separated into bins
    payload_length_freq_bins: Vec<usize>,
    /// Frequency of interarrival times (from client) for this flow,
    /// separated into bins
    interarrival_freq_from_client_bins: Vec<usize>,
    /// Frequency of interarrival times (to client) for this flow,
    /// separated into bins
    interarrival_freq_to_client_bins: Vec<usize>,
}

impl FlowFeatures {
    /// Calculate flow features from a set of packets
    ///
    /// All values that do not fit into a maximum bin size will be ignored. To avoid this, add a
    /// very large bin at the end
    ///
    /// # Parameters:
    /// * `packet_features` - Set of packet features to create flow features from
    /// * `payload_length_bin_sizes` - Set of maximum sizes for each payload length bin
    /// * `interarrival_from_client_bin_sizes` - Set of maximum sizes for each interarrival time bin
    ///                                          (from client)
    /// * `interarrival_to_client_bin_sizes` - Set of maximum sizes for each interarrival time bin
    ///                                        (to client)
    pub fn generate(
        packet_features: &[PacketFeatures],
        payload_length_bin_sizes: &[usize],
        interarrival_from_client_bin_sizes: &[u64],
        interarrival_to_client_bin_sizes: &[u64],
    ) -> Self {
        // Initialize the bins
        let mut payload_length_freq_bins = vec![0; payload_length_bin_sizes.len()];
        let mut interarrival_freq_from_client_bins =
            vec![0; interarrival_from_client_bin_sizes.len()];
        let mut interarrival_freq_to_client_bins = vec![0; interarrival_to_client_bin_sizes.len()];
        // Generate the frequencies
        for packet in packet_features {
            for (idx, bin_max) in payload_length_bin_sizes.iter().enumerate() {
                if packet.payload_length < *bin_max {
                    payload_length_freq_bins[idx] += 1;
                    break;
                }
            }
            for (idx, bin_max) in interarrival_from_client_bin_sizes.iter().enumerate() {
                if packet.direction == PacketDirection::FromClient
                    && packet.interarrival_time < *bin_max
                {
                    interarrival_freq_from_client_bins[idx] += 1;
                    break;
                }
            }
            for (idx, bin_max) in interarrival_to_client_bin_sizes.iter().enumerate() {
                if packet.direction == PacketDirection::ToClient
                    && packet.interarrival_time < *bin_max
                {
                    interarrival_freq_to_client_bins[idx] += 1;
                    break;
                }
            }
        }
        // Return the flow features
        FlowFeatures {
            payload_length_freq_bins,
            interarrival_freq_from_client_bins,
            interarrival_freq_to_client_bins,
        }
    }

    /// Generates an empty set of flow features with all zeroes
    pub fn empty(
        num_payload_length_bins: usize,
        num_ia_from_client_bins: usize,
        num_ia_to_client_bins: usize,
    ) -> Self {
        FlowFeatures {
            payload_length_freq_bins: vec![0; num_payload_length_bins],
            interarrival_freq_from_client_bins: vec![0; num_ia_from_client_bins],
            interarrival_freq_to_client_bins: vec![0; num_ia_to_client_bins],
        }
    }

    /// Normalizes bins
    pub fn normalize(self) -> NormalizedFlowFeatures {
        NormalizedFlowFeatures::from(self)
    }
}
impl ops::Add for FlowFeatures {
    type Output = Self;
    /// Accumulates two flow feature entries. It's assumed that they have the same bin sizes
    fn add(mut self, rhs: Self) -> Self::Output {
        // Add packet size counts
        for (idx, freq) in rhs.payload_length_freq_bins.iter().enumerate() {
            self.payload_length_freq_bins[idx] += freq;
        }
        for (idx, freq) in rhs.interarrival_freq_from_client_bins.iter().enumerate() {
            self.interarrival_freq_from_client_bins[idx] += freq;
        }
        for (idx, freq) in rhs.interarrival_freq_to_client_bins.iter().enumerate() {
            self.interarrival_freq_to_client_bins[idx] += freq;
        }
        self
    }
}

/// Flow features after normalizing each feature
#[derive(Debug, Serialize)]
pub struct NormalizedFlowFeatures {
    /// Frequency of packet sizes for this flow, separated into bins
    #[serde(rename = "pl")]
    pub payload_length_freq_bins: Vec<f64>,
    /// Frequency of interarrival times (from client) for this flow,
    /// separated into bins
    #[serde(rename = "iaf")]
    pub interarrival_freq_from_client_bins: Vec<f64>,
    /// Frequency of interarrival times (to client) for this flow,
    /// separated into bins
    #[serde(rename = "iat")]
    pub interarrival_freq_to_client_bins: Vec<f64>,
}

impl From<FlowFeatures> for NormalizedFlowFeatures {
    fn from(flow_features: FlowFeatures) -> NormalizedFlowFeatures {
        // Get the sum of each field
        let pl_sum = flow_features.payload_length_freq_bins.iter().sum::<usize>();
        let iaf_sum = flow_features
            .interarrival_freq_from_client_bins
            .iter()
            .sum::<usize>();
        let iat_sum = flow_features
            .interarrival_freq_to_client_bins
            .iter()
            .sum::<usize>();
        // Allow handling normalization when all values are zero
        let zero_handler = |d| if d == 0 { 1.0 } else { d as f64 };
        let pl_sum = zero_handler(pl_sum);
        let iaf_sum = zero_handler(iaf_sum);
        let iat_sum = zero_handler(iat_sum);
        // Normalize against sum for each
        let payload_length_freq_bins = flow_features
            .payload_length_freq_bins
            .into_iter()
            .map(|c| c as f64 / pl_sum)
            .collect();
        let interarrival_freq_from_client_bins = flow_features
            .interarrival_freq_from_client_bins
            .into_iter()
            .map(|c| c as f64 / iaf_sum)
            .collect();

        let interarrival_freq_to_client_bins = flow_features
            .interarrival_freq_to_client_bins
            .into_iter()
            .map(|c| c as f64 / iat_sum)
            .collect();
        // Return the normalized flow features
        NormalizedFlowFeatures {
            payload_length_freq_bins,
            interarrival_freq_from_client_bins,
            interarrival_freq_to_client_bins,
        }
    }
}
