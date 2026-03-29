//! Platform-specific file permission helpers.

use std::path::Path;

/// Set directory permissions to owner-only (0o700 on Unix, no-op on Windows).
#[allow(clippy::print_stderr)]
pub const fn set_dir_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        if let Err(e) = std::fs::set_permissions(path, perms) {
            eprintln!(
                "warning: failed to set permissions on {}: {e}",
                path.display()
            );
        }
    }
    let _ = path;
}

/// Set file permissions to owner read/write only (0o600 on Unix, no-op on Windows).
#[allow(clippy::print_stderr)]
pub const fn set_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(path, perms) {
            eprintln!(
                "warning: failed to set permissions on {}: {e}",
                path.display()
            );
        }
    }
    let _ = path;
}
