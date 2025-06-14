use std::fs;
use std::io::{prelude::*, BufReader};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use itertools::Itertools;
use streaming_iterator::StreamingIterator;

use crate::scanner::{ScanError, ScannedData};

struct Mapping<'a> {
    begin: u64,
    end: u64,
    perms: &'a str,
    offset: u64,
    dmaj: u8,
    dmin: u8,
    inode: u64,
    path: &'a str,
}

// Each row in /proc/$PID/maps describes a region of contiguous virtual
// memory in a process or thread. Each row has the following fields:
//
// address           perms offset  dev   inode   pathname
// 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
fn parse_map_line<'a>(line: &'a str) -> Option<Mapping<'a>> {
    let (address, perms, offset, dev, inode, path) =
        line.splitn(6, " ").next_tuple()?;
    let offset = u64::from_str_radix(offset, 16).ok()?;
    let inode = u64::from_str_radix(inode, 16).ok()?;
    let (begin, end) = address.split("-").next_tuple()?;
    let begin = u64::from_str_radix(begin, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let (dmaj, dmin) = dev.split(":").next_tuple()?;
    let dmaj = u8::from_str_radix(dmaj, 16).ok()?;
    let dmin = u8::from_str_radix(dmin, 16).ok()?;
    Some(Mapping { begin, end, perms, offset, dmaj, dmin, inode, path })
}

struct ProcessMemory {
    maps_reader: BufReader<fs::File>,
    mems: fs::File,
    pid: u32,
    buffer: [u8; 0x1000],
    start: u64,
    end: u64,
}

impl ProcessMemory {
    pub fn new(pid: u32) -> Result<Self, ScanError> {
        let maps_path: PathBuf = format!("/proc/{pid}/maps").into();
        let maps = fs::OpenOptions::new()
            .read(true)
            .open(&maps_path)
            .map_err(|err| ScanError::OpenError {
                path: maps_path.to_path_buf(),
                source: err,
            })?;
        let mems_path: PathBuf = format!("/proc/{pid}/mem").into();
        let mems = fs::OpenOptions::new()
            .read(true)
            .open(&mems_path)
            .map_err(|err| ScanError::OpenError {
                path: mems_path.to_path_buf(),
                source: err,
            })?;
        Ok(ProcessMemory {
            maps_reader: BufReader::new(maps),
            mems,
            pid,
            buffer: [0; 0x1000],
            start: 0,
            end: 0,
        })
    }
}

impl StreamingIterator for ProcessMemory {
    type Item = [u8];

    fn get(&self) -> Option<&Self::Item> {
        if self.start < self.end {
            let size = std::cmp::min(self.end - self.start, 0x1000);
            Some(&self.buffer[0..size as usize])
        } else {
            None
        }
    }

    fn advance(self: &mut Self) {
        if self.start < self.end {
            let size = std::cmp::min(self.end - self.start, 0x1000);
            self.start += size;
        }
        if self.start < self.end {
            let size = std::cmp::min(self.end - self.start, 0x1000);
            let _ = self
                .mems
                .read_exact_at(&mut self.buffer[0..size as usize], self.start);
            return;
        } else {
            let mut line = String::new();
            while self
                .maps_reader
                .read_line(&mut line)
                .is_ok_and(|read| read != 0)
            {
                let Some(mapping) = parse_map_line(&line) else {
                    line.clear();
                    continue;
                };
                if !mapping.perms.starts_with("r") {
                    line.clear();
                    continue;
                }
                self.start = mapping.begin;
                self.end = mapping.end;
                let size = std::cmp::min(self.end - self.start, 0x1000);
                let _ = self.mems.read_exact_at(
                    &mut self.buffer[0..size as usize],
                    self.start,
                );
                return;
            }
        }
    }
}

pub fn load_proc(pid: u32) -> Result<ScannedData<'static>, ScanError> {
    let mut process_memory_iter = ProcessMemory::new(pid)?;
    let mut process_memory = Vec::new();

    while let Some(mem_chunck) = process_memory_iter.next() {
        process_memory.extend_from_slice(mem_chunck);
    }

    return Ok(ScannedData::Vec(process_memory));
}

// pub fn load_proc(pid: u32) -> Result<ScannedData<'static>, ScanError> {
//     // let pagemap_fd_path: PathBuf = format!("/proc/{pid}/pagemap").into();
//     // let pagemap_fd = fs::OpenOptions::new().read(true).open(pagemap_fd_path).map_err(|err| {
//     //     ScanError::OpenError { path: pagemap_fd_path, source: err }
//     // })?;
//
//     let mut line = String::new();
//     let mut process_memory: Vec<u8> = Vec::new();
//
//     while reader.read_line(&mut line).map_err(|err| ScanError::OpenError {
//         path: maps_path.to_path_buf(),
//         source: err,
//     })? != 0
//     {
//         let Some(mapping) = parse_map_line(&line) else {
//             continue;
//         };
//         if !mapping.perms.starts_with("r") {
//             continue;
//         }
//         let size = mapping.end - mapping.begin;
//         let prev_end = process_memory.len();
//         process_memory.resize(prev_end + size as usize, 0);
//         // this currently fails on things like vvars, not sure why, might be alright to just
//         // ignore failures.
//         let _ = mem_fd
//             .read_exact_at(&mut process_memory[prev_end..], mapping.begin);
//         line.clear();
//         //     .map_err(|err| ScanError::OpenError {
//         //     path: mem_fd_path.to_path_buf(),
//         //     source: err,
//         // })?;
//
//         // let map_path = Path::new(path);
//         // let mapping: Mapping = Mapping::Uninitialized;
//         // if map_path.has_root()  && !((dmaj == 0) && (dmin == 0)) {
//         //     if let Ok(meta) = fs::metadata(map_path) {
//         //         let device_id = meta.dev();
//         //         // the major and minor are encoded as MMMM Mmmm mmmM MMmm with M being a
//         //         // hex digit of the major and m being of the minor.
//         //         let file_dmaj = ((device_id & 0x00000000000fff00) >>  8) | ((device_id & 0xfffff00000000000) >> 32);
//         //         let file_dmin = (device_id & 0x00000000000000ff) | ((device_id & 0x00000ffffff00000) >> 12);
//         //         if (meta.ino() != inode) || (dmaj != file_dmaj) || (dmin != file_dmin) {
//         //             // Wrong file, may have been replaced. Treat like missing.
//         //             mapping = Mapping::Mem;
//         //         } else if meta.size() < offset + size {
//         //             // Mapping extends past end of file. Treat like missing.
//         //             mapping = Mapping::Mem;
//         //         // S_IFMT = 0170000, S_IFREG = 0100000
//         //         } else if (meta.mode() & 0o170000) != 0o100000 {
//         //             // Correct filesystem object, but not a regular file. Treat like
//         //             // uninitialized mapping.
//         //             mapping = Mapping::Uninitialized;
//         //         } else {
//         //             match fs::OpenOptions::new()
//         //                 .read(true)
//         //                 .open(map_path) {
//         //                 Ok(f) => {
//         //                     match f.metadata() {
//         //                         Ok(file_meta) => {
//         //                             mapping = if (file_meta.dev() == device_id) && (file_meta.ino() == meta.ino()) {
//         //                                 Mapping::File(f)
//         //                             } else {
//         //                                 Mapping::Mem
//         //                             };
//         //
//         //                         }
//         //                         Err(_) => mapping = Mapping::Mem,
//         //                     }
//         //                 }
//         //                 Err(_) => {
//         //                     mapping = Mapping::Mem;
//         //                 }
//         //             };
//         //
//         //         }
//         //     } else {
//         //         // Why should stat fail after file open? Treat like missing.
//         //         mapping = Mapping::Mem;
//         //     }
//         // }
//         // if let Mapping::File(file) = mapping {
//         //     let res = unsafe {
//         //         MmapOptions::new().map(&file)
//         //     };
//         //     match res {
//         //         Err(_) => mapping = Mapping::Mem,
//         //         Ok(mmap) => {
//         //             let context_buffer = Some(mmap);
//         //             //
//         //         }
//         //     }
//         // }
//         // match mapping {
//         //     Mapping::Mem => {
//         //         let prev_end = mem.len();
//         //         mem.resize(prev_end + size as usize, 0);
//         //         mem_fd.read_exact_at(&mut mem[prev_end..], begin);
//         //     }
//         //     Mapping::Uninitialized => {},
//         //     Mapping::File(_) =>,
//         //
//         // }
//     }
//     Ok(ScannedData::Vec(process_memory))
// }
