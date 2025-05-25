use std::fs;
use std::io::{prelude::*, BufReader};
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use itertools::Itertools;
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi;

use crate::scanner::ScanError;

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

#[cfg(target_os = "linux")]
pub fn load_proc(pid: u64) -> Result<Vec<u8>, ScanError> {
    let maps_path: PathBuf = format!("/proc/{pid}/maps").into();
    let maps =
        fs::OpenOptions::new().read(true).open(&maps_path).map_err(|err| {
            ScanError::OpenError { path: maps_path.to_path_buf(), source: err }
        })?;
    let mem_fd_path: PathBuf = format!("/proc/{pid}/mem").into();
    let mem_fd = fs::OpenOptions::new()
        .read(true)
        .open(&mem_fd_path)
        .map_err(|err| ScanError::OpenError {
            path: mem_fd_path.to_path_buf(),
            source: err,
        })?;
    // let pagemap_fd_path: PathBuf = format!("/proc/{pid}/pagemap").into();
    // let pagemap_fd = fs::OpenOptions::new().read(true).open(pagemap_fd_path).map_err(|err| {
    //     ScanError::OpenError { path: pagemap_fd_path, source: err }
    // })?;

    let mut reader = BufReader::new(maps);
    let mut line = String::new();
    let mut process_memory: Vec<u8> = Vec::new();

    while reader.read_line(&mut line).map_err(|err| ScanError::OpenError {
        path: maps_path.to_path_buf(),
        source: err,
    })? != 0
    {
        let Some(mapping) = parse_map_line(&line) else {
            continue;
        };
        if !mapping.perms.starts_with("r") {
            continue;
        }
        let size = mapping.end - mapping.begin;
        let prev_end = process_memory.len();
        process_memory.resize(prev_end + size as usize, 0);
        // this currently fails on things like vvars, not sure why, might be alright to just
        // ignore failures.
        let _ = mem_fd
            .read_exact_at(&mut process_memory[prev_end..], mapping.begin);
        line.clear();
        //     .map_err(|err| ScanError::OpenError {
        //     path: mem_fd_path.to_path_buf(),
        //     source: err,
        // })?;

        // let map_path = Path::new(path);
        // let mapping: Mapping = Mapping::Uninitialized;
        // if map_path.has_root()  && !((dmaj == 0) && (dmin == 0)) {
        //     if let Ok(meta) = fs::metadata(map_path) {
        //         let device_id = meta.dev();
        //         // the major and minor are encoded as MMMM Mmmm mmmM MMmm with M being a
        //         // hex digit of the major and m being of the minor.
        //         let file_dmaj = ((device_id & 0x00000000000fff00) >>  8) | ((device_id & 0xfffff00000000000) >> 32);
        //         let file_dmin = (device_id & 0x00000000000000ff) | ((device_id & 0x00000ffffff00000) >> 12);
        //         if (meta.ino() != inode) || (dmaj != file_dmaj) || (dmin != file_dmin) {
        //             // Wrong file, may have been replaced. Treat like missing.
        //             mapping = Mapping::Mem;
        //         } else if meta.size() < offset + size {
        //             // Mapping extends past end of file. Treat like missing.
        //             mapping = Mapping::Mem;
        //         // S_IFMT = 0170000, S_IFREG = 0100000
        //         } else if (meta.mode() & 0o170000) != 0o100000 {
        //             // Correct filesystem object, but not a regular file. Treat like
        //             // uninitialized mapping.
        //             mapping = Mapping::Uninitialized;
        //         } else {
        //             match fs::OpenOptions::new()
        //                 .read(true)
        //                 .open(map_path) {
        //                 Ok(f) => {
        //                     match f.metadata() {
        //                         Ok(file_meta) => {
        //                             mapping = if (file_meta.dev() == device_id) && (file_meta.ino() == meta.ino()) {
        //                                 Mapping::File(f)
        //                             } else {
        //                                 Mapping::Mem
        //                             };
        //
        //                         }
        //                         Err(_) => mapping = Mapping::Mem,
        //                     }
        //                 }
        //                 Err(_) => {
        //                     mapping = Mapping::Mem;
        //                 }
        //             };
        //
        //         }
        //     } else {
        //         // Why should stat fail after file open? Treat like missing.
        //         mapping = Mapping::Mem;
        //     }
        // }
        // if let Mapping::File(file) = mapping {
        //     let res = unsafe {
        //         MmapOptions::new().map(&file)
        //     };
        //     match res {
        //         Err(_) => mapping = Mapping::Mem,
        //         Ok(mmap) => {
        //             let context_buffer = Some(mmap);
        //             //
        //         }
        //     }
        // }
        // match mapping {
        //     Mapping::Mem => {
        //         let prev_end = mem.len();
        //         mem.resize(prev_end + size as usize, 0);
        //         mem_fd.read_exact_at(&mut mem[prev_end..], begin);
        //     }
        //     Mapping::Uninitialized => {},
        //     Mapping::File(_) =>,
        //
        // }
    }
    println!("memory size = {:x}", process_memory.len());
    Ok(process_memory)
}

#[cfg(target_os = "windows")]
pub fn load_proc(pid: u64) -> Result<Vec<u8>, ScanError> {
  if (processthreadsapi::OpenProcessToken(processthreadsapi::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) &&
      LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug))
  {
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luidDebug;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(
        hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
  }

  if (hToken != NULL)
    CloseHandle(hToken);

  proc_info->hProcess = OpenProcess(
      PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

  if (proc_info->hProcess == NULL)
  {
    yr_free(proc_info);
    return ERROR_COULD_NOT_ATTACH_TO_PROCESS;
  }

  GetSystemInfo(&proc_info->si);
}
