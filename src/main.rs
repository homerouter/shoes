#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// jemalloc reads this `const char *` at startup; `_RJEM_MALLOC_CONF` still overrides it.
// Background purging returns idle memory, and two arenas suffice for small VPS nodes.
#[cfg(target_os = "linux")]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
static malloc_conf: Option<&u8> =
    Some(&b"background_thread:true,narenas:2,dirty_decay_ms:1000,thp:never\0"[0]);

// Host THP=always backs sparse allocator extents and thread stacks with 2 MiB pages.
// Runs from .init_array so it precedes the runtime's first allocation.
#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static DISABLE_THP: extern "C" fn() = {
    extern "C" fn disable_thp() {
        unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) };
    }
    disable_thp
};

fn main() {
    shoes::cli::main();
}
