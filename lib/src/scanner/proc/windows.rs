use std::mem::MaybeUninit;
use std::os::windows::io::{
    AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle,
};

use windows::Win32::{
    Foundation::{ERROR_PARTIAL_COPY, HANDLE, LUID},
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
use windows_result::HRESULT;

use crate::scanner::proc::DataIter;
use crate::scanner::ScanError;

struct ProcessMapping {
    address: u64,
    max_address: u64,
}

impl ProcessMapping {
    fn new() -> Self {
        let mut maybe_si = MaybeUninit::<SYSTEM_INFO>::uninit();

        let si = unsafe {
            GetSystemInfo(maybe_si.as_mut_ptr());
            maybe_si.assume_init()
        };

        let min_address = si.lpMinimumApplicationAddress as u64;
        let max_address = si.lpMaximumApplicationAddress as u64;

        Self { address: min_address, max_address }
    }

    fn next<'a>(
        &mut self,
        h_process: BorrowedHandle<'a>,
    ) -> Option<MEMORY_BASIC_INFORMATION> {
        let mut mbi_maybe = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();

        if (self.address < self.max_address)
            && unsafe {
                VirtualQueryEx(
                    HANDLE(h_process.as_raw_handle()),
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

pub struct ProcessMemory {
    h_process: OwnedHandle,
    maps: ProcessMapping,
    start: u64,
    end: u64,
}

impl ProcessMemory {
    pub fn new(pid: u32) -> Result<Self, ScanError> {
        // TODO: this should be done once for the entire entire scanning process, not once per process
        // loaded.
        obtain_debug_priv()
            .map_err(|err| ScanError::ProcessError { pid, err })?;

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

        Ok(Self { h_process, maps: ProcessMapping::new(), start: 0, end: 0 })
    }
}

// TODO: Make this configurable.
const MAX_BUFFER_SIZE: u64 = 0x100000;
const ERROR_PARTIAL_COPY_RESULT: HRESULT =
    HRESULT::from_win32(ERROR_PARTIAL_COPY.0);

impl DataIter for ProcessMemory {
    type Item<'a> = &'a Vec<u8>;
    fn next<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Option<Self::Item<'a>> {
        buffer.clear();
        loop {
            if self.start < self.end {
                let size =
                    std::cmp::min(MAX_BUFFER_SIZE, self.end - self.start);
                if size as usize > buffer.capacity() {
                    buffer.reserve_exact(size as usize);
                }
                let mut read: usize = 0;
                unsafe {
                    if !ReadProcessMemory(
                        HANDLE(self.h_process.as_raw_handle()),
                        self.start as *const core::ffi::c_void,
                        std::mem::transmute::<_, &mut [u8]>(
                            buffer.spare_capacity_mut(),
                        )
                        .as_mut_ptr()
                            as *mut core::ffi::c_void,
                        size as usize,
                        Some(&mut read),
                    )
                    .map_err(|e| match e.code() {
                        // This is expected, we just read less than the requested size.
                        ERROR_PARTIAL_COPY_RESULT => Ok(()),
                        _ => Err(e),
                    })
                    .is_ok()
                    {
                        self.start += size;
                        continue;
                    }
                    buffer.set_len(read);
                }
                self.start += read as u64;
                return Some(buffer);
            } else if let Some(mbi) =
                self.maps.next(self.h_process.as_handle())
            {
                // NOTE: think about maybe touching PAGE_GUARD twice to enable reading from it.
                if (!mbi.State.contains(MEM_COMMIT))
                    || mbi.Protect.contains(PAGE_NOACCESS)
                {
                    continue;
                }
                self.start = mbi.BaseAddress as u64;
                self.end = self.start + mbi.RegionSize as u64;
            } else {
                return None;
            }
        }
    }
}
