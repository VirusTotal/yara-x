#[cfg(target_os = "linux")]
pub use linux::ProcessMemory;
#[cfg(target_os = "windows")]
pub use windows::ProcessMemory;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

pub trait DataIter {
    type Item<'a>: AsRef<[u8]>;
    fn next<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Option<Self::Item<'a>>;
}
