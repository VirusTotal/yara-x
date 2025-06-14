use std::mem::MaybeUninit;

use itertools::Itertools;
use memmap2::MmapOptions;
use winapi::{
    shared::{basetsd, minwindef, ntdef},
    um::{
        handleapi, memoryapi, processthreadsapi, securitybaseapi, sysinfoapi,
        winbase, winnt,
    },
};

use crate::scanner::{ScanError, ScannedData};

struct ProcessMapping {
    address: u64,
    max_address: u64,
    h_process: winnt::HANDLE,
}

impl ProcessMapping {
    pub fn new(h_process: winnt::HANDLE) -> Self {
        let mut maybe_si = MaybeUninit::<sysinfoapi::SYSTEM_INFO>::uninit();

        let si = unsafe {
            sysinfoapi::GetSystemInfo(maybe_si.as_mut_ptr());
            maybe_si.assume_init()
        };

        let min_address = si.lpMinimumApplicationAddress as u64;
        let max_address = si.lpMaximumApplicationAddress as u64;

        Self { h_process, address: min_address, max_address }
    }
}

impl Iterator for ProcessMapping {
    type Item = winnt::MEMORY_BASIC_INFORMATION;

    fn next(&mut self) -> Option<Self::Item> {
        let mut mbi_maybe =
            MaybeUninit::<winnt::MEMORY_BASIC_INFORMATION>::uninit();

        if (self.address < self.max_address)
            && unsafe {
                memoryapi::VirtualQueryEx(
                    self.h_process,
                    self.address as *const winapi::ctypes::c_void,
                    mbi_maybe.as_mut_ptr(),
                    size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
                ) != 0
            }
        {
            let mbi = unsafe { mbi_maybe.assume_init() };
            self.address = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
            Some(mbi)
        } else {
            None
        }
    }
}

fn obtain_debug_priv() -> bool {
    let mut h_token: winnt::HANDLE = ntdef::NULL;
    let mut luid_debug_maybe = MaybeUninit::<winnt::LUID>::uninit();
    let res = if let Some(luid_debug) = unsafe {
        if (processthreadsapi::OpenProcessToken(
            processthreadsapi::GetCurrentProcess(),
            winnt::TOKEN_ADJUST_PRIVILEGES,
            &mut h_token,
        ) != minwindef::FALSE)
            && (winbase::LookupPrivilegeValueA(
                std::ptr::null(),
                winnt::SE_DEBUG_NAME.as_ptr() as *const i8,
                luid_debug_maybe.as_mut_ptr(),
            ) != minwindef::FALSE)
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
                minwindef::FALSE,
                &mut token_priv,
                size_of::<winnt::TOKEN_PRIVILEGES>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) != minwindef::FALSE
        }
    } else {
        false
    };

    if h_token != ntdef::NULL {
        unsafe {
            handleapi::CloseHandle(h_token);
        }
    };
    return res;
}

pub fn load_proc(pid: u32) -> Result<ScannedData<'static>, ScanError> {
    // TODO: this should be done once for the entire entire scanning process, not once per process
    // loaded.
    obtain_debug_priv();

    let h_process = unsafe {
        processthreadsapi::OpenProcess(
            winnt::PROCESS_VM_READ | winnt::PROCESS_QUERY_INFORMATION,
            minwindef::FALSE,
            pid,
        )
    };

    if h_process == ntdef::NULL {
        return Err(ScanError::ProcessError { pid, source: None });
    }

    let process_mappings = ProcessMapping::new(h_process)
        .filter(|mbi| {
            (mbi.State == winnt::MEM_COMMIT)
                && ((mbi.Protect & winnt::PAGE_NOACCESS) == 0)
        })
        .collect_vec();

    let memory_size: u64 =
        process_mappings.iter().map(|mbi| mbi.RegionSize as u64).sum();

    let mut process_memory = MmapOptions::new()
        .len(memory_size as usize)
        .map_anon()
        .map_err(|err| ScanError::ProcessError { pid, source: Some(err) })?;
    let mut offset = 0;

    for mbi in process_mappings {
        if unsafe {
            let mut read = MaybeUninit::<basetsd::SIZE_T>::uninit();
            memoryapi::ReadProcessMemory(
                h_process,
                mbi.BaseAddress,
                process_memory[offset as usize..].as_mut_ptr()
                    as *mut winapi::ctypes::c_void,
                mbi.RegionSize,
                read.as_mut_ptr(),
            ) != 0
        } {
            offset += mbi.RegionSize;
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
