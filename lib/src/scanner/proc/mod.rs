#[cfg(target_os = "linux")]
pub use linux::ProcessMemory;
#[cfg(target_os = "windows")]
pub use windows::ProcessMemory;

use memmap2::Mmap;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
