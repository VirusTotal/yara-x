use std::mem::MaybeUninit;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use itertools::Itertools;
use memmap2::MmapOptions;
use windows::Win32::{
    Foundation::{HANDLE, LUID},
    Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
        SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES,
    },
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
            PAGE_NOACCESS,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        },
    },
};
use windows_result;

use crate::scanner::{ScanError, ScannedData};

struct ProcessMapping<'a> {
    address: u64,
    max_address: u64,
    h_process: &'a OwnedHandle,
}

impl<'a> ProcessMapping<'a> {
    pub fn new(h_process: &'a OwnedHandle) -> Self {
        let mut maybe_si = MaybeUninit::<SYSTEM_INFO>::uninit();

        let si = unsafe {
            GetSystemInfo(maybe_si.as_mut_ptr());
            maybe_si.assume_init()
        };

        let min_address = si.lpMinimumApplicationAddress as u64;
        let max_address = si.lpMaximumApplicationAddress as u64;

        Self { h_process, address: min_address, max_address }
    }
}

impl<'a> Iterator for ProcessMapping<'a> {
    type Item = MEMORY_BASIC_INFORMATION;

    fn next(&mut self) -> Option<Self::Item> {
        let mut mbi_maybe = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();

        if (self.address < self.max_address)
            && unsafe {
                VirtualQueryEx(
                    HANDLE(self.h_process.as_raw_handle()),
                    Some(self.address as *const core::ffi::c_void),
                    mbi_maybe.as_mut_ptr(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
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

fn obtain_debug_priv() -> Result<(), windows_result::Error> {
    let mut h_token_maybe = MaybeUninit::<HANDLE>::uninit();
    let h_token = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES,
            h_token_maybe.as_mut_ptr(),
        )?;
        OwnedHandle::from_raw_handle(h_token_maybe.assume_init().0)
    };
    let mut luid_debug_maybe = MaybeUninit::<LUID>::uninit();
    let luid_debug = unsafe {
        LookupPrivilegeValueW(
            None,
            SE_DEBUG_NAME,
            luid_debug_maybe.as_mut_ptr(),
        )?;
        luid_debug_maybe.assume_init()
    };

    let mut token_priv = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid_debug,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe {
        AdjustTokenPrivileges(
            HANDLE(h_token.as_raw_handle()),
            false,
            Some(&mut token_priv),
            size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )?
    };

    Ok(())
}

pub fn load_proc(pid: u32) -> Result<ScannedData<'static>, ScanError> {
    // TODO: this should be done once for the entire entire scanning process, not once per process
    // loaded.
    obtain_debug_priv().map_err(|err| ScanError::ProcessError { pid, err })?;

    let h_process = unsafe {
        OwnedHandle::from_raw_handle(
            OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            )
            .map_err(|err| ScanError::ProcessError { pid, err })?
            .0,
        )
    };

    let process_mappings = ProcessMapping::new(&h_process)
        .filter(|mbi| {
            (mbi.State == MEM_COMMIT) && (!mbi.Protect.contains(PAGE_NOACCESS))
        })
        .collect_vec();

    let memory_size: u64 =
        process_mappings.iter().map(|mbi| mbi.RegionSize as u64).sum();

    let mut process_memory = MmapOptions::new()
        .len(memory_size as usize)
        .map_anon()
        .map_err(|err| ScanError::AnonMapError { source: err })?;
    let mut offset = 0;

    for mbi in process_mappings {
        let mut read: usize = 0;
        unsafe {
            _ = ReadProcessMemory(
                HANDLE(h_process.as_raw_handle()),
                mbi.BaseAddress,
                process_memory[offset as usize..].as_mut_ptr()
                    as *mut core::ffi::c_void,
                mbi.RegionSize,
                Some(&mut read),
            );
        };
        offset += read;
    }

    Ok(ScannedData::Mmap(
        process_memory
            .make_read_only()
            .map_err(|err| ScanError::AnonMapError { source: err })?,
    ))
}
