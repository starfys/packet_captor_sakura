use byteorder::{BigEndian, LittleEndian, NativeEndian, ReadBytesExt};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub struct PcapReader<T> {
    source: T,
    endianness: Endianness,
    pub is_nanosecond_res: bool,
    header: PcapHeader,
}

impl PcapReader<BufReader<File>> {
    /// Constructor from a filename
    pub fn open(path: &Path) -> Result<Self, io::Error> {
        // Open the PCAP file
        let pcap_file: File = File::open(path)?;
        let reader = BufReader::new(pcap_file);
        // Initialize the pcap reader from the BufReader
        PcapReader::from_reader(reader)
    }
}
impl<T> PcapReader<T>
where
    T: Read,
{
    /// Constructor from a reader
    pub fn from_reader(mut source: T) -> Result<Self, io::Error> {
        // Read in magic number using the system's endianness
        let magic_number = source.read_u32::<NativeEndian>()?;
        // Determine endianness
        // used to detect the file format itself and the byte ordering. The writing
        // application writes 0xa1b2c3d4 with it's native byte ordering format into
        // this field. The reading application will read either 0xa1b2c3d4 (identical)
        // or 0xd4c3b2a1 (swapped). If the reading application reads the swapped 0xd4c3b2a1
        // value, it knows that all the following fields will have to be swapped too. For
        // nanosecond-resolution files, the writing application writes 0xa1b23c4d, with
        // the two nibbles of the two lower-order bytes swapped, and the reading
        // application will read either 0xa1b23c4d (identical) or 0x4d3cb2a1 (swapped).
        let (is_flipped, is_nanosecond_res): (bool, bool) = match magic_number {
            0xa1b2_c3d4 => (false, false),
            0xd4c3_b2a1 => (true, false),
            0xa1b2_3c4d => (false, true),
            0x4d3c_b2a1 => (true, true),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid magic number: {}", magic_number),
                ));
            }
        };
        // Determine the endiannness based on whether the read is flipped
        // Always use the native endianness if possible
        // This code is compiled on little endian systems
        #[cfg(target_endian = "little")]
        let endianness: Endianness = if is_flipped {
            Endianness::Big
        } else {
            Endianness::Little
        };
        // This code is compiled on big endian systems
        #[cfg(target_endian = "big")]
        let endianness: Endianness = if is_flipped {
            Endianness::Little
        } else {
            Endianness::Big
        };
        // Read in the header
        let header = PcapHeader::read_from(&mut source, &endianness)?;
        // Construct the reader
        Ok(PcapReader {
            source,
            endianness,
            is_nanosecond_res,
            header,
        })
    }
}
impl<T> Iterator for PcapReader<T>
where
    T: Read,
{
    /// Each item is a Pcap record
    type Item = PcapRecord;
    /// Reads a record from the source
    fn next(&mut self) -> Option<Self::Item> {
        PcapRecord::read_from(&mut self.source, &self.endianness).ok()
    }
}

/// The header at the beginning of each PCAP file
/// Implements PCAP as specified by [libpcap](https://wiki.wireshark.org/Development/LibpcapFileFormat)
/// Magic number is skipped because its data is considered part of the reader
#[derive(Debug)]
struct PcapHeader {
    // Magic number
    //pub magic_number: u32,
    /// Major version number
    pub version_major: u16,
    /// Minor version number
    pub version_minor: u16,
    /// GMT to local correction
    pub this_zone: i32,
    /// Accuracy of timestamps
    pub sig_figs: u32,
    /// Max length of captured packets, in octets
    pub snap_len: u32,
    /// Data link type
    pub network: u32,
}
impl PcapHeader {
    /// Reads in the pcap header from some source using the given endianness
    fn read_from<'a, T: 'a>(
        mut source: &'a mut T,
        endianness: &Endianness,
    ) -> Result<Self, io::Error>
    where
        T: Read,
    {
        // Read each of the fields
        // ? will cause the function to return with any error encountered
        let version_major: u16 = endianness.read_u16(&mut source)?;
        let version_minor: u16 = endianness.read_u16(&mut source)?;
        let this_zone: i32 = endianness.read_i32(&mut source)?;
        let sig_figs: u32 = endianness.read_u32(&mut source)?;
        let snap_len: u32 = endianness.read_u32(&mut source)?;
        let network: u32 = endianness.read_u32(&mut source)?;
        Ok(PcapHeader {
            version_major,
            version_minor,
            this_zone,
            sig_figs,
            snap_len,
            network,
        })
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
    /// Reads in the pcap header from some source using the given endianness
    fn read_from<'a, T: 'a>(
        mut source: &'a mut T,
        endianness: &Endianness,
    ) -> Result<Self, io::Error>
    where
        T: Read,
    {
        // Read each of the fields
        let ts_sec = endianness.read_u32(&mut source)?;
        let ts_usec = endianness.read_u32(&mut source)?;
        let incl_len = endianness.read_u32(&mut source)?;
        let orig_len = endianness.read_u32(&mut source)?;
        // Construct the header
        Ok(PcapRecordHeader {
            ts_sec,
            ts_usec,
            incl_len,
            orig_len,
        })
    }

    /// Returns the timestamp as a `Duration` object
    #[allow(dead_code)]
    pub fn get_time_as_duration(&self, is_nanosecond_res: bool) -> Duration {
        Duration::new(
            u64::from(self.ts_sec),
            if is_nanosecond_res {
                self.ts_usec
            } else {
                self.ts_usec * 1000
            },
        )
    }
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

impl PcapRecord {
    /// Reads in the pcap header from some source using the given endianness
    fn read_from<'a, T: 'a>(
        mut source: &'a mut T,
        endianness: &Endianness,
    ) -> Result<Self, io::Error>
    where
        T: Read,
    {
        // Read the header
        let header = PcapRecordHeader::read_from(&mut source, endianness)?;
        // Read the number of bytes specified in the header
        // FIXME: conversion here is potentially unsafe
        let mut data: Vec<u8> = vec![0; header.incl_len as usize];
        source.read_exact(&mut data)?;
        // Construct the header
        Ok(PcapRecord { header, data })
    }
}
/// Used when we need to store the endianness of input data
#[derive(Debug)]
enum Endianness {
    /// Big endian
    Big,
    /// Little endian
    Little,
}
impl Endianness {
    /// Reads a u32 from the source
    fn read_u32<'a, T: 'a>(&self, source: &'a mut T) -> Result<u32, io::Error>
    where
        T: Read,
    {
        match *self {
            Endianness::Big => source.read_u32::<BigEndian>(),
            Endianness::Little => source.read_u32::<LittleEndian>(),
        }
    }
    /// Reads a i32 from the source
    fn read_i32<'a, T: 'a>(&self, source: &'a mut T) -> Result<i32, io::Error>
    where
        T: Read,
    {
        match *self {
            Endianness::Big => source.read_i32::<BigEndian>(),
            Endianness::Little => source.read_i32::<LittleEndian>(),
        }
    }
    /// Reads a u16 from the source
    fn read_u16<'a, T: 'a>(&self, source: &'a mut T) -> Result<u16, io::Error>
    where
        T: Read,
    {
        match *self {
            Endianness::Big => source.read_u16::<BigEndian>(),
            Endianness::Little => source.read_u16::<LittleEndian>(),
        }
    }
}
