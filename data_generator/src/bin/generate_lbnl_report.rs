use clap::{Arg, App, crate_version, crate_authors};
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use url_queue::capture::{CaptureWork, CaptureWorkType};
use url_queue::work::WorkReportRequest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let matches = App::new("LBNL packet dataset report generator")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Generates report.json in the desired format from the LBNL packet dataset")
        .arg(
            Arg::with_name("dataset_path")
                .help("Path to the directory containing the LBNL packet dataset")
                .value_name("DATASET_PATH")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::with_name("include_scanners")
                .takes_value(false)
                .short("-s")
                .long("--include-scanners")
                .help("Whether to include data from scanners")
        )
        .get_matches();
    // Get dataset path
    let dataset_path: PathBuf = matches
        .value_of("dataset_path")
        .expect("Path to LBNL dataset missing")
        .parse()
        .expect("Failed to parse path to LBNL dataset");
    // Get whether to include scanner files
    let include_scanners = matches.is_present("include_scanners");

    // Do some checks
    if !dataset_path.is_dir() {
        panic!("Dataset path is not directory");
    }
    // Get directory iterator
    let dir_iter = dataset_path.read_dir()?;
    // Generate report file
    let report_path = dataset_path.join("report.json");
    let report_file = OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .open(report_path)?;
    // Wrap report file  in a buffered writer
    let mut report_writer = BufWriter::new(report_file);
    // Iterate over files in directory
    for (idx, dir_entry) in dir_iter.enumerate() {
        // Unwrap the directory entry
        let dir_entry = dir_entry?;
        // Check the filename
        let file_path = dir_entry.path();
        let extension = file_path.extension().unwrap();
        if extension == "anon" || (extension == "anon-scanners" && include_scanners) {
            let idx: u64 = idx.try_into().unwrap();
            // Construct a report
            let work = WorkReportRequest {
                success: true,
                work_type: CaptureWorkType::Normal,
                work: CaptureWork {
                    index: idx,
                    url: "unknown".to_string(),
                    filename: file_path
                },
                type_index: idx,
                start_time: 0,
                finish_time: 0
            };
            // Output the json
            serde_json::to_writer(&mut report_writer, &work)?;
            report_writer.write(b"\n")?;
        }
    }

    Ok(())

}
