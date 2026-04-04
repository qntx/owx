//! Shared blocking HTTP client for x402 operations.

use std::sync::LazyLock;
use std::time::Duration;

use crate::error::PayError;

pub static CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
});

pub fn send_request(
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<reqwest::blocking::Response, PayError> {
    let mut req = match method.to_uppercase().as_str() {
        "POST" => CLIENT.post(url),
        "PUT" => CLIENT.put(url),
        "DELETE" => CLIENT.delete(url),
        "PATCH" => CLIENT.patch(url),
        _ => CLIENT.get(url),
    };
    if let Some(b) = body {
        req = req
            .header("Content-Type", "application/json")
            .body(b.to_owned());
    }
    if let Some(ph) = payment_header {
        req = req.header("X-PAYMENT", ph);
    }
    Ok(req.send()?)
}
