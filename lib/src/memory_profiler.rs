/*! Memory profiling and OOM prevention using DHAT.

When the `dhat-heap` feature is enabled, this module provides [`DhatThresholdAllocator`],
a custom global allocator wrapping `dhat::Alloc`. It monitors process memory usage and
automatically triggers an early DHAT callstack profile dump to `stdout` if memory usage
crosses a configurable soft limit (via environment variable `YRX_MEMORY_LIMIT_MB` or `YARA_X_MEMORY_LIMIT_MB`,
defaulting to 4096 MB).
*/

#[cfg(feature = "dhat-heap")]
mod impl_dhat {
    use std::alloc::{GlobalAlloc, Layout};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;

    /// Default soft OOM limit: 4 GB (4096 MB) unless overridden by env var YRX_MEMORY_LIMIT_MB or YARA_X_MEMORY_LIMIT_MB.
    const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 4096 * 1024 * 1024;

    static TOTAL_ALLOCATED: AtomicU64 = AtomicU64::new(0);
    static MEMORY_LIMIT_BYTES: AtomicU64 = AtomicU64::new(DEFAULT_MEMORY_LIMIT_BYTES);
    static IS_DUMPING: AtomicBool = AtomicBool::new(false);
    static PROFILER: Mutex<Option<dhat::Profiler>> = Mutex::new(None);

    thread_local! {
        static IN_ALLOC: Cell<bool> = const { Cell::new(false) };
    }

    /// Global allocator wrapper around [`dhat::Alloc`] that enforces a soft memory cap
    /// and flushes DHAT profiling data to `stdout` before process termination on OOM.
    pub struct DhatThresholdAllocator;

    unsafe impl GlobalAlloc for DhatThresholdAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // Re-entrancy guard: if we are already inside our allocator checks,
            // directly delegate to dhat::Alloc to prevent infinite recursion.
            let reentrant = IN_ALLOC.with(|cell| {
                if cell.get() {
                    true
                } else {
                    cell.set(true);
                    false
                }
            });

            if reentrant {
                return unsafe { dhat::Alloc.alloc(layout) };
            }

            let size = layout.size() as u64;
            let current = TOTAL_ALLOCATED.fetch_add(size, Ordering::Relaxed) + size;
            let limit = MEMORY_LIMIT_BYTES.load(Ordering::Relaxed);

            if current >= limit {
                trigger_early_dhat_dump(current, limit);
            }

            let ptr = unsafe { dhat::Alloc.alloc(layout) };

            IN_ALLOC.with(|cell| cell.set(false));

            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let reentrant = IN_ALLOC.with(|cell| {
                if cell.get() {
                    true
                } else {
                    cell.set(true);
                    false
                }
            });

            unsafe { dhat::Alloc.dealloc(ptr, layout) };

            if !reentrant {
                TOTAL_ALLOCATED.fetch_sub(layout.size() as u64, Ordering::Relaxed);
                IN_ALLOC.with(|cell| cell.set(false));
            }
        }
    }

    #[derive(serde::Deserialize)]
    struct DhatData {
        pps: Vec<DhatPp>,
        ftbl: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct DhatPp {
        tb: u64,
        tbk: u64,
        mb: u64,
        fs: Vec<usize>,
    }

    fn format_bytes(bytes: u64) -> String {
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Formats and prints DHAT JSON profile data into a legible table on stdout.
    pub fn print_readable_dhat_report(json_str: &str) {
        let data: DhatData = match serde_json::from_str(json_str) {
            Ok(d) => d,
            Err(_) => {
                println!("{}", json_str);
                return;
            }
        };

        let mut pps = data.pps;
        pps.sort_by(|a, b| b.mb.cmp(&a.mb).then_with(|| b.tb.cmp(&a.tb)));

        println!("\n=================================================================================");
        println!("                    YARA-X TOP HEAP ALLOCATIONS REPORT                           ");
        println!("=================================================================================");
        println!(
            "{:<4}  {:<12}  {:<12}  {:<8}  {}",
            "RANK", "MAX LIVE", "TOTAL ALLOC", "BLOCKS", "CALL SITE / LOCATION"
        );
        println!("---------------------------------------------------------------------------------");

        let mut count = 0;
        for pp in pps {
            if pp.tb == 0 && pp.mb == 0 {
                continue;
            }

            let mut chosen_frame = "Unknown";
            for &f_idx in &pp.fs {
                if let Some(frame_str) = data.ftbl.get(f_idx) {
                    let clean = if let Some(pos) = frame_str.find(": ") {
                        &frame_str[pos + 2..]
                    } else {
                        frame_str.as_str()
                    };

                    let is_boilerplate = clean.starts_with("<alloc::")
                        || clean.starts_with("alloc::")
                        || clean.starts_with("dhat::")
                        || clean.starts_with("<dhat::")
                        || clean.starts_with("hashbrown::")
                        || clean.starts_with("<hashbrown::")
                        || clean.starts_with("std::alloc")
                        || clean.starts_with("core::alloc")
                        || clean.starts_with("std::sys")
                        || clean.starts_with("__rustc::")
                        || clean.contains("DhatThresholdAllocator");

                    if !is_boilerplate {
                        chosen_frame = clean;
                        break;
                    }
                    if chosen_frame == "Unknown" {
                        chosen_frame = clean;
                    }
                }
            }

            count += 1;
            println!(
                "{:>3}.  {:<12}  {:<12}  {:<8}  {}",
                count,
                format_bytes(pp.mb),
                format_bytes(pp.tb),
                pp.tbk,
                chosen_frame
            );

            if count >= 20 {
                break;
            }
        }
        println!("=================================================================================\n");
    }

    fn trigger_early_dhat_dump(current_bytes: u64, limit_bytes: u64) {
        if IS_DUMPING.swap(true, Ordering::SeqCst) {
            return;
        }

        eprintln!("\n==================================================================");
        eprintln!(
            "  [YARA-X OOM PREVENTED] Heap allocation crossed soft limit! ({:.2} MB / {:.2} MB)",
            current_bytes as f64 / (1024.0 * 1024.0),
            limit_bytes as f64 / (1024.0 * 1024.0)
        );
        eprintln!("  Generating readable memory profiling report...");
        eprintln!("==================================================================\n");

        if let Ok(mut guard) = PROFILER.lock() {
            if let Some(profiler) = guard.take() {
                drop(profiler);
            }
        }

        // Parse dhat-heap.json and print human-readable table to stdout
        if let Ok(content) = std::fs::read_to_string("dhat-heap.json") {
            print_readable_dhat_report(&content);
            let _ = std::fs::remove_file("dhat-heap.json");
        }

        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();

        panic!(
            "YARA-X soft OOM threshold reached: {:.2} MB (Limit: {:.2} MB)",
            current_bytes as f64 / (1024.0 * 1024.0),
            limit_bytes as f64 / (1024.0 * 1024.0)
        );
    }

    /// Initializes the DHAT profiler and configures soft memory limit from environment.
    pub fn init_dhat_profiler() {
        if let Ok(val) = std::env::var("YRX_MEMORY_LIMIT_MB")
            .or_else(|_| std::env::var("YARA_X_MEMORY_LIMIT_MB"))
        {
            if let Ok(mb) = val.parse::<u64>() {
                MEMORY_LIMIT_BYTES.store(mb * 1024 * 1024, Ordering::Relaxed);
            }
        }

        let profiler = dhat::Profiler::new_heap();
        if let Ok(mut guard) = PROFILER.lock() {
            *guard = Some(profiler);
        }
    }

    /// Returns the configured soft memory limit in bytes.
    pub fn memory_limit_bytes() -> u64 {
        MEMORY_LIMIT_BYTES.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_memory_limit_parsing() {
            unsafe {
                std::env::set_var("YRX_MEMORY_LIMIT_MB", "512");
            }
            init_dhat_profiler();
            assert_eq!(memory_limit_bytes(), 512 * 1024 * 1024);
            unsafe {
                std::env::remove_var("YRX_MEMORY_LIMIT_MB");
            }
        }
    }
}

#[cfg(feature = "dhat-heap")]
pub use impl_dhat::*;
