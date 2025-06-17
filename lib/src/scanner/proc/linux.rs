use std::fs;
use std::io::{prelude::*, BufReader};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use itertools::Itertools;
use memmap2::MmapOptions;

use crate::scanner::{ScanError, ScannedData};

struct Mapping {
    begin: u64,
    end: u64,
    perms: String,
    offset: u64,
    dmaj: u8,
    dmin: u8,
    inode: u64,
    path: String,
}

// Each row in /proc/$PID/maps describes a region of contiguous virtual
// memory in a process or thread. Each row has the following fields:
//
// address           perms offset  dev   inode   pathname
// 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
fn parse_map_line(line: &str) -> Option<Mapping> {
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
    Some(Mapping {
        begin,
        end,
        perms: perms.to_string(),
        offset,
        dmaj,
        dmin,
        inode,
        path: path.to_string(),
    })
}

struct ProcessMapping {
    maps_reader: BufReader<fs::File>,
}

impl ProcessMapping {
    pub fn new(pid: u32) -> Result<Self, ScanError> {
        let maps_path: PathBuf = format!("/proc/{pid}/maps").into();
        let maps = fs::OpenOptions::new()
            .read(true)
            .open(&maps_path)
            .map_err(|err| ScanError::OpenError {
                path: maps_path.to_path_buf(),
                source: err,
            })?;
        Ok(Self { maps_reader: BufReader::new(maps) })
    }
}

impl Iterator for ProcessMapping {
    type Item = Mapping;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        while self.maps_reader.read_line(&mut line).is_ok_and(|read| read != 0)
        {
            let Some(mapping) = parse_map_line(&line) else {
                line.clear();
                continue;
            };
            return Some(mapping);
        }
        return None;
    }
}

// struct ProcessMemory<'a, T> {
//     mappings: T,
//     mems: fs::File,
//     buffer: &'a mut [u8],
//     offset: u64,
//     start: u64,
//     end: u64,
// }
//
// impl<'a, T> ProcessMemory<'a, T> {
//     pub fn new(
//         pid: u32,
//         mappings: T,
//         buffer: &'a mut [u8],
//     ) -> Result<Self, ScanError> {
//         let mems_path: PathBuf = format!("/proc/{pid}/mem").into();
//         let mems = fs::OpenOptions::new()
//             .read(true)
//             .open(&mems_path)
//             .map_err(|err| ScanError::OpenError {
//                 path: mems_path.to_path_buf(),
//                 source: err,
//             })?;
//
//         Ok(Self { mappings, mems, buffer, offset: 0, start: 0, end: 0 })
//     }
// }
//
// impl<'a, T> Iterator for ProcessMemory<'a, T>
// where
//     T: Iterator<Item = Mapping>,
// {
//     type Item = ();
//
//     fn next(self: &mut Self) -> Option<Self::Item> {
//         if self.start < self.end {
//             let size =
//                 std::cmp::min(self.end - self.start, self.buffer.len() as u64);
//             self.start += size;
//         }
//         if self.start < self.end {
//             let size =
//                 std::cmp::min(self.end - self.start, self.buffer.len() as u64);
//             let _ = self
//                 .mems
//                 .read_exact_at(&mut self.buffer[0..size as usize], self.start);
//             return Some(());
//         } else {
//             while let Some(mapping_desc) = self.mappings.next() {
//                 self.start = mapping_desc.begin;
//                 self.end = mapping_desc.end;
//                 let size = std::cmp::min(
//                     self.end - self.start,
//                     self.buffer.len() as u64,
//                 );
//                 let _ = self.mems.read_exact_at(
//                     &mut self.buffer[0..size as usize],
//                     self.start,
//                 );
//                 return Some(());
//             }
//         }
//         return None;
//     }
// }

pub fn load_proc(pid: u32) -> Result<ScannedData<'static>, ScanError> {
    let process_mappings = ProcessMapping::new(pid)?
        .filter(|mapping| mapping.perms.starts_with("r"))
        .collect_vec();
    let memory_size: u64 = process_mappings
        .iter()
        .map(|mapping| mapping.end - mapping.begin)
        .sum();
    let mut process_memory =
        MmapOptions::new().len(memory_size as usize).map_anon().map_err(
            |err| ScanError::OpenError { path: "".into(), source: err },
        )?;

    let mems_path: PathBuf = format!("/proc/{pid}/mem").into();
    let mems =
        fs::OpenOptions::new().read(true).open(&mems_path).map_err(|err| {
            ScanError::OpenError { path: mems_path.to_path_buf(), source: err }
        })?;

    let mut offset: u64 = 0;
    for mapping in process_mappings {
        let size = mapping.end - mapping.begin;
        if mems
            .read_exact_at(
                &mut process_memory[offset as usize..(offset + size) as usize],
                mapping.begin,
            )
            .is_ok()
        {
            offset += size;
        }
    }

    // let mut process_memory_iter =
    //     ProcessMemory::new(pid, process_mappings.iter(), &mut process_memory)?;

    Ok(ScannedData::Mmap(
        process_memory
            .make_read_only()
            .map_err(|err| ScanError::AnonMapError { err })?,
    ))
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
