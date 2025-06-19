use std::fs;
use std::io::{prelude::*, BufReader};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::PathBuf;

use bitflags::bitflags;
use itertools::Itertools;
use memmap2::{MmapMut, MmapOptions};

use crate::scanner::{ScanError, ScannedData};

bitflags! {
    #[derive(Debug)]
    pub struct Perms: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
        const EXECUTE = 0b00000100;
        const SHARED = 0b00001000;
    }
}

#[derive(Debug)]
pub struct Mapping {
    begin: u64,
    end: u64,
    perms: Perms,
    offset: u64,
    dmaj: u8,
    dmin: u8,
    inode: u64,
    pathname: String,
}

impl Mapping {
    fn open_backing_file(&self) -> Option<fs::File> {
        if (self.pathname.len() == 0) || ((self.dmaj == 0) && (self.dmin == 0))
        {
            return None;
        }
        let meta = fs::metadata(&self.pathname).ok()?;
        let dev = meta.dev();

        if (libc::major(dev) != self.dmaj as u32)
            || (libc::minor(dev) != self.dmin as u32)
            || (meta.ino() != self.inode)
            || (meta.size() < self.offset)
            || ((meta.mode() & libc::S_IFMT) != libc::S_IFREG)
        {
            return None;
        }

        let file =
            fs::OpenOptions::new().read(true).open(&self.pathname).ok()?;
        let meta = file.metadata().ok()?;
        let dev = meta.dev();

        if (libc::major(dev) != self.dmaj as u32)
            || (libc::minor(dev) != self.dmin as u32)
            || (meta.ino() != self.inode)
            || (meta.size() < self.offset)
            || ((meta.mode() & libc::S_IFMT) != libc::S_IFREG)
        {
            return None;
        }

        Some(file)
    }
}

// Each row in /proc/$PID/maps describes a region of contiguous virtual
// memory in a process or thread. Each row has the following fields:
//
// address           perms offset  dev   inode   pathname
// 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
// The following might be problematic:
// "pathname is shown unescaped except for newline characters,
// which are replaced with an octal escape sequence.  As a
// result, it is not possible to determine whether the
// original pathname contained a newline character or the
// literal \012 character sequence."
fn parse_map_line(line: &str) -> Option<Mapping> {
    let (address, str_perms, offset, dev, inode, pathname) =
        line.splitn(6, " ").next_tuple()?;
    // this is fine because a valid path must start with a '/', we only strip a single '\n'
    // character because the path can technically contain whitespace characters.
    let pathname = pathname.trim_start().strip_suffix('\n').unwrap_or("");
    let offset = u64::from_str_radix(offset, 16).ok()?;
    let inode = u64::from_str_radix(inode, 10).ok()?;
    let (begin, end) = address.split("-").next_tuple()?;
    let begin = u64::from_str_radix(begin, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let (dmaj, dmin) = dev.split(":").next_tuple()?;
    let dmaj = u8::from_str_radix(dmaj, 16).ok()?;
    let dmin = u8::from_str_radix(dmin, 16).ok()?;
    let str_perms = str_perms.bytes().collect_vec();
    if str_perms.len() != 4 {
        return None;
    }
    let mut perms = Perms::empty();
    if str_perms[0] == b'r' {
        perms |= Perms::READ;
    }
    if str_perms[1] == b'w' {
        perms |= Perms::WRITE;
    }
    if str_perms[2] == b'x' {
        perms |= Perms::EXECUTE;
    }
    if str_perms[3] == b's' {
        perms |= Perms::SHARED;
    }
    Some(Mapping {
        begin,
        end,
        perms,
        offset,
        dmaj,
        dmin,
        inode,
        pathname: pathname.to_string(),
    })
}

pub struct ProcessMapping {
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
                err,
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
            match parse_map_line(&line) {
                Some(mapping) => return Some(mapping),
                None => {
                    line.clear();
                    continue;
                }
            }
        }
        return None;
    }
}

pub struct ProcessMemory {
    maps: ProcessMapping,
    mem: fs::File,
    pagemap: fs::File,
    pagesize: usize,
}

impl ProcessMemory {
    pub fn new(pid: u32) -> Result<Self, ScanError> {
        let maps = ProcessMapping::new(pid)?;
        let mem_path: PathBuf = format!("/proc/{pid}/mem").into();
        let mem = fs::OpenOptions::new().read(true).open(&mem_path).map_err(
            |err| ScanError::OpenError { path: mem_path.to_path_buf(), err },
        )?;

        let pagemap_path: PathBuf = format!("/proc/{pid}/pagemap").into();
        let pagemap = fs::OpenOptions::new()
            .read(true)
            .open(&pagemap_path)
            .map_err(|err| ScanError::OpenError {
                path: pagemap_path.to_path_buf(),
                err,
            })?;

        Ok(Self {
            maps,
            mem,
            pagemap,
            pagesize: unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) }
                .try_into()
                .unwrap_or(4096),
        })
    }
}

impl Iterator for ProcessMemory {
    // the static here is meaningless because we never return a ScannedData::Slice, which is the
    // only one that makes use of the lifetime.
    type Item = ScannedData<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(map) = self.maps.next() {
            if !map.perms.contains(Perms::READ) {
                continue;
            }

            let size = (map.end - map.begin) as usize;
            match map
                .open_backing_file()
                .map(|file| unsafe {
                    MmapOptions::new()
                        .offset(map.offset)
                        .len(size)
                        .map_copy(&file)
                        .ok()
                })
                .flatten()
            {
                Some(mut mapped_file) => {
                    let mut pagemap = Box::<[u64]>::new_uninit_slice(
                        size.div_ceil(self.pagesize),
                    );
                    self.pagemap
                        .read_exact_at(
                            unsafe { pagemap.align_to_mut() }.1,
                            map.offset,
                        )
                        .ok()?;
                    let pagemap = unsafe { pagemap.assume_init() };

                    for (index, detail) in pagemap.iter().enumerate() {
                        if (detail >> 61) == 0 {
                            continue;
                        }

                        let start = index * self.pagesize;
                        self.mem
                            .read_exact_at(
                                &mut mapped_file[start..start + self.pagesize],
                                map.begin + start as u64,
                            )
                            .ok()?;
                    }

                    return Some(ScannedData::Mmap(
                        mapped_file.make_read_only().ok()?,
                    ));
                }
                None => {
                    // NOTE: consider reusing the buffer, and using MaybeUninit.
                    let mut buffer = Vec::<u8>::with_capacity(size);
                    self.mem
                        .read_exact_at(
                            unsafe {
                                std::mem::transmute(
                                    buffer.spare_capacity_mut(),
                                )
                            },
                            map.begin,
                        )
                        .ok()?;
                    unsafe {
                        buffer.set_len(size);
                    };
                    return Some(ScannedData::Vec(buffer));
                }
            }
        }
        None
    }
}

pub fn load_proc(pid: u32) -> Result<ScannedData<'static>, ScanError> {
    let process_mappings = ProcessMapping::new(pid)?
        .filter(|mapping| mapping.perms.contains(Perms::READ))
        .collect_vec();
    let memory_size: u64 = process_mappings
        .iter()
        .map(|mapping| mapping.end - mapping.begin)
        .sum();
    let mut process_memory = MmapOptions::new()
        .len(memory_size as usize)
        .map_anon()
        .map_err(|err| ScanError::OpenError { path: "".into(), err })?;

    let mems_path: PathBuf = format!("/proc/{pid}/mem").into();
    let mems =
        fs::OpenOptions::new().read(true).open(&mems_path).map_err(|err| {
            ScanError::OpenError { path: mems_path.to_path_buf(), err }
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
