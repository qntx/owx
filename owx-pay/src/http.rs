//! Shared blocking HTTP client for all owx-pay operations.

use std::sync::LazyLock;
use std::time::Duration;

/// Global blocking HTTP client with a 30-second timeout.
pub static CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
});
