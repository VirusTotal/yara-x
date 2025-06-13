#[cfg(target_os = "linux")]
pub use linux::load_proc;
#[cfg(target_os = "windows")]
pub use windows::load_proc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
