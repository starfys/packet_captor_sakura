use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bro_types::Connection;
use crate::features::{
    DirectionInferenceMethod, FlowFeatures, NormalizedFlowFeatures, PacketFeatures,
};
use crate::flow_aggregator::FlowAggregator;
use crate::packet::Packet;

use failure::Error;
use flate2::write::GzEncoder;
use flate2::Compression;
use itertools::Itertools;
use rayon::prelude::*;
use tempdir::TempDir;

use url_queue::capture::{CaptureWork, CaptureWorkType};
use url_queue::work::WorkReportRequest;

pub struct Dataset {
    classes: HashMap<CaptureWorkType, Vec<FlowData>>,
}

impl Dataset {
    /// Loads a dataset from a directory
    pub fn load<P>(data_dir: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // Copy path
        let data_dir = data_dir.as_ref();
        // Ensure the data directory is a directory
        ensure!(data_dir.is_dir(), "Path to dataset must be a directory");
        // Open the report
        let mut report_path = PathBuf::from(data_dir);
        report_path.push("report.json");
        ensure!(report_path.is_file(), "Data path must contain report.json");
        let report_file = File::open(report_path)?;
        let report_file = BufReader::new(report_file);
        // Read and parse report file
        let mut work: Vec<WorkReportRequest<CaptureWorkType, CaptureWork>> = report_file
            .lines()
            .flatten()
            .flat_map(|line| serde_json::from_str(&line))
            .collect();
        // Sort reports by type and name
        work.par_sort_unstable_by_key(|report| (report.work_type, report.work.index));
        // Extract data from each work item
        let classes = work
            .into_par_iter()
            // Filter out failed work
            .filter(|report| report.success)
            // Load flow data from the PCAP for this work
            .flat_map(|report| FlowData::load(report, data_dir))
            // Separate out group type so we can aggregate
            .map(|flow_data| (flow_data.class, flow_data))
            // Collect into one big vector
            .collect::<Vec<_>>()
            // Convert to iterator for itertools
            .into_iter()
            // Group by type
            .into_group_map();
        Ok(Dataset { classes })
    }

    // Saves a dataset to a json file
    /// # Parameters
    /// * `output_path` - Path to write the class datasets to
    pub fn save<P>(self, output_path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        // This type is used to represent flows as tensors instead of raw features
        #[derive(Serialize)]
        struct FlowDataTensor {
            #[serde(rename = "c")]
            class: CaptureWorkType,
            #[serde(rename = "u")]
            url: String,
            #[serde(rename = "f")]
            is_first_of_class: bool,
            #[serde(rename = "pl")]
            payload_length_freq_bins: Vec<f64>,
            #[serde(rename = "iaf")]
            interarrival_freq_from_client_bins: Vec<f64>,
            #[serde(rename = "iat")]
            interarrival_freq_to_client_bins: Vec<f64>,
        };
        impl FlowDataTensor {
            fn from_flow_data(flow: FlowData) -> Self {
                FlowDataTensor {
                    class: flow.class,
                    url: flow.url,
                    is_first_of_class: flow.is_first_of_class,
                    payload_length_freq_bins: flow.features.payload_length_freq_bins,
                    interarrival_freq_from_client_bins: flow
                        .features
                        .interarrival_freq_from_client_bins,
                    interarrival_freq_to_client_bins: flow
                        .features
                        .interarrival_freq_to_client_bins,
                }
            }
        }
        // Save each class
        for (class, flows) in self.classes {
            let class_filename = output_path
                .as_ref()
                .join(class.to_string())
                .with_extension("json.gz");
            // Open a write handle to the file
            let output_file = File::create(class_filename)?;
            let output_file_writer = BufWriter::new(output_file);
            // Write to the file using gzip
            let mut gz_writer = GzEncoder::new(output_file_writer, Compression::fast());
            // Write bytes from each data point to the file
            for flow in flows {
                serde_json::to_writer(&mut gz_writer, &FlowDataTensor::from_flow_data(flow))?;
                gz_writer.write(b"\n")?;
            }
            // Flush the writer
            gz_writer.flush()?;
        }
        Ok(())
    }
}

/// Represents data from a single flow. Many of these can exist per pcap file
#[derive(Debug)]
pub struct FlowData {
    /// Class of data gathered in this pcap
    class: CaptureWorkType,
    /// The URL that was requested that this flow was performed as part of
    url: String,
    /// Whether this pcap was the first of its class to be run on the worker
    /// This matters for meek (first time initialization)
    pub is_first_of_class: bool,
    /// Features of the packets of this flow
    features: NormalizedFlowFeatures,
}
impl FlowData {
    /// Loads a class dataset from a directory
    #[allow(unused)]
    pub fn load<P>(
        report: WorkReportRequest<CaptureWorkType, CaptureWork>,
        data_path: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // Split report
        let WorkReportRequest {
            work_type: class,
            work,
            type_index,
            ..
        } = report;
        // Split work
        let CaptureWork { url, filename, .. } = work;
        // Copy the paths
        let data_path = data_path.as_ref();
        // Create a scratch dir
        // TODO: change name here when we change the crate name
        let scratch_dir = TempDir::new("data_generator")?;
        // Get path to scratch dir
        let scratch_path = scratch_dir.path();
        // Ensure the data directory is a directory
        ensure!(data_path.is_dir(), "Class directory must be a directory");
        // Iterate over the PCAP files in the class directory
        // Get path to the pcap file using the data directory and filename
        let pcap_path = data_path.join(filename);
        // Ensure pcap_file is a file
        ensure!(
            pcap_path.is_file(),
            "Items in a class directory must be files"
        );
        // Ensure the scratch directory is a directory
        ensure!(
            scratch_path.is_dir(),
            "Scratch directory must be a directory"
        );
        // Run BRO on the pcap file
        info!("Running bro on {:?}", pcap_path);
        let bro_return = Command::new("bro")
            .current_dir(scratch_path)
            .arg("-b")
            .arg("-e")
            .arg("redef LogAscii::use_json=T")
            .arg("-C")
            .arg("-r")
            .arg(
                pcap_path
                    .to_str()
                    .ok_or_else(|| format_err!("Path string could not be parsed"))?,
            )
            .arg("base/protocols/conn")
            .status()?;
        info!("Finished running bro on {:?}", pcap_path);
        // Check error code
        ensure!(bro_return.success(), "Bro exited with failure code");
        info!("Loading connection log for {:?}", pcap_path);
        // Load the connection log
        let conn_log_path = scratch_path.join("conn.log");
        let connections = Connection::load_connections(&conn_log_path)?
            .filter(|connection| connection.orig_port == 443 || connection.resp_port == 443);
        // Delete the bro folder
        info!("Cleaning up bro scratch dir");
        scratch_dir.close()?;
        // Read in packets from the pcap
        info!("Loading packets from {:?}", pcap_path);
        let packets = Packet::load_from_pcap(&pcap_path)?
            .filter(|packet| packet.src_port == 443 || packet.dst_port == 443)
            .collect();
        // Aggregate the connection log and pcap
        // Initialize a flow aggregator
        info!("Performing packet aggregation");
        let mut flow_aggregator = FlowAggregator::new(connections, 1_000_000_000, 5_000_000_000);
        // Load the packets into the aggregator
        flow_aggregator.load_packets(packets);
        // Create a set of directional inference methods
        // TODO: take this as config
        let dir_inference_methods = vec![DirectionInferenceMethod::ServerPort(443)];
        // Create a set of feature generation bins
        // TODO: take this as config
        let payload_size_bins: Vec<usize> = (10..=100)
            .step_by(10)
            .chain((200..=1000).step_by(100))
            .chain((2000..=10000).step_by(1000))
            .chain(Some(65536))
            .collect();
        // Create variable so it's easier to keep track of time periods
        // Our timestamps are in nanoseconds. Convert here to ms
        let ms: u64 = 1_000_000;
        let interarrival_from_client_bins: Vec<u64> = (1 * ms..=10 * ms)
            .step_by(1 * ms as usize)
            .chain((20 * ms..=100 * ms).step_by(10 * ms as usize))
            .chain((200 * ms..=1000 * ms).step_by(100 * ms as usize))
            .chain(Some(10_000 * ms))
            .collect();
        // Use the same periods for to_client
        let interarrival_to_client_bins = interarrival_from_client_bins.clone();
        // Extract the aggregated flows from the aggregator
        let (num_flows, features) = flow_aggregator
            .into_aggregated_flows()
            .into_iter()
            // Convert each flow's packets into features
            .map(move |(_, packets)| {
                PacketFeatures::from_stripped_packets(packets, &dir_inference_methods)
            })
            // Encapsulate the flow
            .map(|features| {
                FlowFeatures::generate(
                    &features,
                    &payload_size_bins,
                    &interarrival_from_client_bins,
                    &interarrival_to_client_bins,
                )
            })
            // Aggregate the many flows associated with a request into a single flow
            .fold(
                (
                    0,
                    FlowFeatures::empty(
                        payload_size_bins.len(),
                        interarrival_from_client_bins.len(),
                        interarrival_to_client_bins.len(),
                    ),
                ),
                |(count, flow_acc), flow| (0, flow_acc + flow),
            );
        Ok(FlowData {
            class,
            url: url.clone(),
            is_first_of_class: type_index == 1,
            features: features.normalize(),
        })
    }
}

#[derive(Serialize)]
struct ClassMetadata {
    num_samples: usize,
    sample_size: Vec<usize>,
}
impl ClassMetadata {
    fn new(num_samples: usize, sample_size: Vec<usize>) -> Self {
        ClassMetadata {
            num_samples,
            sample_size,
        }
    }
}
