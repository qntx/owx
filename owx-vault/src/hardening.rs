//! Process-level security hardening for key material protection.
//!
//! Provides OS primitives to reduce the risk of key material leaking via
//! core dumps, debugger attachment, or memory swapping.
//!
//! Also provides signal-based cleanup hooks so that cached key material
//! is zeroized on termination signals before the process exits.

use std::sync::{Mutex, OnceLock};

/// Global registry of cleanup functions to run on termination signals.
type CleanupHooks = Mutex<Vec<Box<dyn Fn() + Send>>>;
static CLEANUP_HOOKS: OnceLock<CleanupHooks> = OnceLock::new();

fn hooks() -> &'static Mutex<Vec<Box<dyn Fn() + Send>>> {
    CLEANUP_HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a cleanup function to run when a termination signal is received.
///
/// Typical usage: register a closure that clears a key cache.
pub fn register_cleanup(f: impl Fn() + Send + 'static) {
    #[allow(clippy::expect_used)]
    hooks()
        .lock()
        .expect("cleanup hooks lock")
        .push(Box::new(f));
}

/// Run all registered cleanup hooks.
fn run_cleanup_hooks() {
    if let Some(hooks_mutex) = CLEANUP_HOOKS.get()
        && let Ok(hooks_vec) = hooks_mutex.lock() {
            for hook in hooks_vec.iter() {
                hook();
            }
        }
}

/// Report of which hardening measures succeeded.
#[derive(Debug, Clone, Copy)]
pub struct HardeningReport {
    /// Whether core dumps were successfully disabled.
    pub core_dumps_disabled: bool,
    /// Whether ptrace/debugger attachment was disabled.
    pub ptrace_disabled: bool,
}

/// Apply all available process hardening measures.
///
/// On Unix: disables core dumps and ptrace attachment.
/// On other platforms: no-op (returns false for both).
#[must_use]
pub const fn harden_process() -> HardeningReport {
    #[cfg(unix)]
    {
        let core_dumps_disabled = disable_core_dumps();
        let ptrace_disabled = disable_ptrace();
        HardeningReport {
            core_dumps_disabled,
            ptrace_disabled,
        }
    }
    #[cfg(not(unix))]
    {
        HardeningReport {
            core_dumps_disabled: false,
            ptrace_disabled: false,
        }
    }
}

/// Install signal handlers for graceful shutdown with key zeroization.
///
/// On Unix: spawns a background thread that waits for SIGTERM, SIGINT, SIGHUP,
/// or SIGQUIT, runs all cleanup hooks, then exits. Also installs a panic hook.
///
/// On other platforms: installs only the panic hook.
///
/// Must be called at most once; subsequent calls are no-ops.
pub fn install_signal_handlers() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        run_cleanup_hooks();
        default_hook(info);
    }));

    #[cfg(unix)]
    install_unix_signal_handlers();
}

#[cfg(unix)]
fn install_unix_signal_handlers() {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    use signal_hook::iterator::Signals;

    #[allow(clippy::expect_used)]
    let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP, SIGQUIT])
        .expect("failed to register signal handlers");

    #[allow(clippy::expect_used)]
    std::thread::Builder::new()
        .name("owx-signal-handler".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("owx: received signal {sig}, zeroizing key material and exiting");
                }
                run_cleanup_hooks();
                std::process::exit(128 + sig);
            }
        })
        .expect("failed to spawn signal handler thread");
}

#[cfg(target_os = "linux")]
fn disable_core_dumps() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        let prctl_ok = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rlimit_ok = libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0;
        prctl_ok && rlimit_ok
    }
}

#[cfg(target_os = "macos")]
fn disable_core_dumps() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_core_dumps() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0
    }
}

#[cfg(target_os = "linux")]
fn disable_ptrace() -> bool {
    true // PR_SET_DUMPABLE=0 already prevents ptrace on Linux
}

#[cfg(target_os = "macos")]
fn disable_ptrace() -> bool {
    #[cfg(not(debug_assertions))]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        #[allow(unsafe_code)]
        unsafe {
            libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0
        }
    }
    #[cfg(debug_assertions)]
    {
        true // Allow debuggers in dev builds
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_ptrace() -> bool {
    false
}

/// Lock a memory region to prevent it from being swapped to disk.
#[cfg(unix)]
pub fn mlock_slice(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[allow(unsafe_code)]
    let ret = unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) };
    ret == 0
}

/// Lock a memory region (no-op on non-Unix).
#[cfg(not(unix))]
pub const fn mlock_slice(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// Unlock a previously mlocked memory region.
#[cfg(unix)]
pub fn munlock_slice(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[allow(unsafe_code)]
    unsafe {
        libc::munlock(ptr.cast::<libc::c_void>(), len);
    }
}

/// Unlock a memory region (no-op on non-Unix).
#[cfg(not(unix))]
pub const fn munlock_slice(_ptr: *const u8, _len: usize) {}

/// Read an environment variable and remove it from the process environment.
pub fn clear_env_var(name: &str) -> Option<String> {
    let value = std::env::var(name).ok();
    #[allow(deprecated, unsafe_code)]
    // SAFETY: We accept the documented UB risk of remove_var in multi-threaded
    // programs. This function is only called during single-threaded startup.
    unsafe {
        std::env::remove_var(name);
    }
    value
}
