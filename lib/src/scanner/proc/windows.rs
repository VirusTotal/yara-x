use std::fs;
use std::io::{prelude::*, BufReader};
use std::mem;
use std::mem::MaybeUninit;
use std::path::PathBuf;

use itertools::Itertools;
#[cfg(target_os = "windows")]
use winapi::{
    shared::{basetsd, ntdef},
    um::{
        handleapi, memoryapi, processthreadsapi, securitybaseapi, sysinfoapi,
        winbase, winnt,
    },
};

use memmap2::{Mmap, MmapOptions};

use crate::scanner::{ScanError, ScannedData};

pub fn load_proc(pid: u32) -> Result<ScannedData<'static>, ScanError> {
    let mut h_token: winnt::HANDLE = ntdef::NULL;
    let mut luid_debug_maybe = MaybeUninit::<winnt::LUID>::uninit();
    if let Some(luid_debug) = unsafe {
        if (processthreadsapi::OpenProcessToken(
            processthreadsapi::GetCurrentProcess(),
            winnt::TOKEN_ADJUST_PRIVILEGES,
            &mut h_token,
        ) != 0)
            && (winbase::LookupPrivilegeValueA(
                std::ptr::null(),
                winnt::SE_DEBUG_NAME.as_ptr() as *const i8,
                luid_debug_maybe.as_mut_ptr(),
            ) != 0)
        {
            Some(luid_debug_maybe.assume_init())
        } else {
            None
        }
    } {
        let mut token_priv = winnt::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [winnt::LUID_AND_ATTRIBUTES {
                Luid: luid_debug,
                Attributes: winnt::SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe {
            securitybaseapi::AdjustTokenPrivileges(
                h_token,
                0,
                &mut token_priv,
                size_of::<winnt::TOKEN_PRIVILEGES>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }
    }

    if h_token != ntdef::NULL {
        unsafe {
            handleapi::CloseHandle(h_token);
        }
    };

    let h_process = unsafe {
        processthreadsapi::OpenProcess(
            winnt::PROCESS_VM_READ | winnt::PROCESS_QUERY_INFORMATION,
            0,
            pid,
        )
    };

    if h_process == ntdef::NULL {
        return Err(ScanError::ProcessError { pid, source: None });
    }

    let mut maybe_si = MaybeUninit::<sysinfoapi::SYSTEM_INFO>::uninit();

    let si = unsafe {
        sysinfoapi::GetSystemInfo(maybe_si.as_mut_ptr());
        maybe_si.assume_init()
    };

    let mut mbi_maybe =
        MaybeUninit::<winnt::MEMORY_BASIC_INFORMATION>::uninit();

    let mut address: u64 = si.lpMinimumApplicationAddress as u64;

    let mut expected_total_size: u64 = 0;

    while let Some(mbi) = if (address < si.lpMaximumApplicationAddress as u64)
        && unsafe {
            memoryapi::VirtualQueryEx(
                h_process,
                address as *const winapi::ctypes::c_void,
                mbi_maybe.as_mut_ptr(),
                size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        } {
        Some(unsafe { mbi_maybe.assume_init() })
    } else {
        None
    } {
        if (mbi.State == winnt::MEM_COMMIT)
            && ((mbi.Protect & winnt::PAGE_NOACCESS) == 0)
        {
            let size =
                mbi.RegionSize as u64 - (address - mbi.BaseAddress as u64);
            expected_total_size += size;
            address += size;
        } else {
            address = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
        }
    }

    address = si.lpMinimumApplicationAddress as u64;

    let mut process_memory = MmapOptions::new()
        .len(expected_total_size as usize)
        .map_anon()
        .map_err(|err| ScanError::ProcessError { pid, source: Some(err) })?;
    let mut offset = 0;

    while let Some(mbi) = if (address < si.lpMaximumApplicationAddress as u64)
        && unsafe {
            memoryapi::VirtualQueryEx(
                h_process,
                address as *const winapi::ctypes::c_void,
                mbi_maybe.as_mut_ptr(),
                size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        } {
        Some(unsafe { mbi_maybe.assume_init() })
    } else {
        None
    } {
        if (mbi.State == winnt::MEM_COMMIT)
            && ((mbi.Protect & winnt::PAGE_NOACCESS) == 0)
        {
            let size =
                mbi.RegionSize as u64 - (address - mbi.BaseAddress as u64);

            if offset + size < expected_total_size {
                if unsafe {
                    let mut read = MaybeUninit::<basetsd::SIZE_T>::uninit();
                    memoryapi::ReadProcessMemory(
                        h_process,
                        address as *const winapi::ctypes::c_void,
                        process_memory[offset as usize..].as_mut_ptr()
                            as *mut winapi::ctypes::c_void,
                        size as usize,
                        read.as_mut_ptr(),
                    ) != 0
                } {
                    offset += size;
                }
            }
            address += size;
        } else {
            address = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
        }
    }

    unsafe {
        handleapi::CloseHandle(h_process);
    }

    Ok(ScannedData::Mmap(
        process_memory.make_read_only().map_err(|err| {
            ScanError::ProcessError { pid, source: Some(err) }
        })?,
    ))
}
