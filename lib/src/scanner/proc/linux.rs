use std::fs;
use std::io::{prelude::*, BufReader};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::PathBuf;

use bitflags::bitflags;
use itertools::Itertools;
use memmap2::{Mmap, MmapOptions};

use crate::scanner::proc::DataIter;
use crate::scanner::ScanError;

pub enum MemRegion<'a> {
    Vec(&'a Vec<u8>),
    Mmap(Mmap),
}

impl AsRef<[u8]> for MemRegion<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            MemRegion::Vec(v) => v.as_ref(),
            MemRegion::Mmap(m) => m.as_ref(),
        }
    }
}

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
    start: u64,
    end: u64,
}

impl ProcessMemory {
    pub fn new(pid: u32) -> Result<Self, ScanError> {
        // TODO: might need to do PTRACE_ATTACH, but it appears to work without it...
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
            start: 0,
            end: 0,
        })
    }
}

// TODO: Make this configurable.
// NOTE: should this also effect Mmap?
const MAX_BUFFER_SIZE: u64 = 0x100000;

impl DataIter for ProcessMemory {
    type Item<'a> = MemRegion<'a>;
    fn next<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Option<MemRegion<'a>> {
        buffer.clear();
        'outer: loop {
            if self.start < self.end {
                let size =
                    std::cmp::min(MAX_BUFFER_SIZE, self.end - self.start);
                if size as usize > buffer.capacity() {
                    buffer.reserve_exact(size as usize);
                }
                if self
                    .mem
                    .read_exact_at(
                        unsafe {
                            std::mem::transmute(buffer.spare_capacity_mut())
                        },
                        self.start,
                    )
                    .is_ok()
                {
                    self.start += size;
                    continue;
                }
                unsafe {
                    buffer.set_len(size as usize);
                };
                self.start += size;
                return Some(MemRegion::Vec(buffer));
            } else if let Some(map) = self.maps.next() {
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
                        let mut region_pagemap =
                            Box::<[u64]>::new_uninit_slice(
                                size.div_ceil(self.pagesize),
                            );
                        if self
                            .pagemap
                            .read_exact_at(
                                unsafe { region_pagemap.align_to_mut() }.1,
                                map.offset,
                            )
                            .is_ok()
                        {
                            let region_pagemap =
                                unsafe { region_pagemap.assume_init() };

                            for (index, detail) in
                                region_pagemap.iter().enumerate()
                            {
                                if (detail >> 61) == 0 {
                                    continue;
                                }

                                let start = index * self.pagesize;
                                if !self
                                    .mem
                                    .read_exact_at(
                                        &mut mapped_file
                                            [start..start + self.pagesize],
                                        map.begin + start as u64,
                                    )
                                    .is_ok()
                                {
                                    continue 'outer;
                                }
                            }
                        } else {
                            if !self
                                .mem
                                .read_exact_at(&mut mapped_file, map.begin)
                                .is_ok()
                            {
                                continue;
                            }
                        }

                        return Some(MemRegion::Mmap(
                            mapped_file.make_read_only().ok()?,
                        ));
                    }
                    None => {
                        self.start = map.begin;
                        self.end = map.end;
                    }
                }
            } else {
                return None;
            }
        }
    }
}
