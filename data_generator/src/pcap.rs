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

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::Linktype;
use std::convert::TryInto;
use std::fs::File;

use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;


pub struct PcapReader2<R> {
    reader: Box<dyn PcapReaderIterator<R>>,
    network: Linktype,
}

impl PcapReader2<BufReader<File>> {
    /// Constructor from a filename
    pub fn open(path: &Path) -> Result<Self, pcap_parser::PcapError> {
        // Open the PCAP file
        let pcap_file: File = File::open(path).unwrap();
        let reader = BufReader::new(pcap_file);
        // Initialize the pcap reader from the BufReader
        PcapReader2::from_reader(reader)
    }
}
impl<R: 'static> PcapReader2<R>
where
    R: Read,
{
    //TODO: return result
    pub fn from_reader(rdr: R) -> Result<Self, pcap_parser::PcapError> {
        let mut reader = pcap_parser::create_reader(2 << 20, rdr)?;
        if let Ok((offset, pcap_parser::PcapBlockOwned::LegacyHeader(header))) = reader.next() {
            reader.consume(offset);
            Ok(Self {
                reader,
                network: header.network,
            })
        } else {
            panic!("Failed to initialize reader");
        }
    }
}

impl<R: 'static> Iterator for PcapReader2<R>
where
    R: Read,
{
    type Item = PcapRecord;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    use pcap_parser::PcapBlockOwned::*;
                    match block {
                        Legacy(block) => {
                            let header = PcapRecordHeader {
                                ts_sec: block.ts_sec,
                                ts_usec: block.ts_usec,
                                incl_len: block.caplen,
                                orig_len: block.origlen,
                            };
                            let data = if let Some(pcap_parser::data::PacketData::L2(data)) =
                                pcap_parser::data::get_packetdata(
                                    block.data,
                                    self.network,
                                    block.caplen.try_into().unwrap(),
                                ) {
                                data.to_vec()
                            } else {
                                Vec::new()
                            };
                            self.reader.consume(offset);
                            return Some(PcapRecord { header, data });
                        }
                        NG(_block) => {
                            println!("PCAPNGBLOCK");
                            self.reader.consume(offset);
                        }
                        LegacyHeader(_header) => {
                            self.reader.consume(offset);
                        }
                    };
                }
                Err(pcap_parser::PcapError::Eof) => {
                    return None;
                }
                Err(pcap_parser::PcapError::Incomplete) => {
                    self.reader.refill().unwrap();
                }
                Err(e) => panic!("Error reading pcap: {:?}", e),
            }
        }
    }
}

/// The header before each packet
#[derive(Debug)]
pub struct PcapRecordHeader {
    /// Timestamp seconds
    ts_sec: u32,
    /// Timestamp microseconds
    ts_usec: u32,
    /// Number of octets of packet saved in file
    incl_len: u32,
    /// Actual length of packet
    orig_len: u32,
}

impl PcapRecordHeader {
    /// Returns the timestamp as nanoseconds
    pub fn get_time_as_nanos(&self, is_nanosecond_res: bool) -> u64 {
        // Convert seconds to nanoseconds
        u64::from(self.ts_sec) * 1_000_000_000
            + if is_nanosecond_res {
                // If nanosecond res, usec is
                // already nanoseconds
                u64::from(self.ts_usec)
            } else {
                // Else, multiply by 1000 to get us->ns
                u64::from(self.ts_usec) * 1000
            }
    }
}

/// A header/data pair
#[derive(Debug)]
pub struct PcapRecord {
    /// The record's pcap header
    pub header: PcapRecordHeader,
    /// The record's data
    pub data: Vec<u8>,
}
