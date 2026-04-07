//! EIP-3009 `TransferWithAuthorization` typed data construction.

/// Build EIP-712 typed data JSON for `TransferWithAuthorization`.
#[allow(
    clippy::too_many_arguments,
    reason = "EIP-712 typed data requires all these fields"
)]
pub(super) fn build_typed_data(
    token_name: &str,
    token_version: &str,
    chain_id: &str,
    verifying_contract: &str,
    from: &str,
    to: &str,
    value: &str,
    valid_after: &str,
    valid_before: &str,
    nonce: &str,
) -> String {
    serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"}
            ]
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id,
            "verifyingContract": verifying_contract
        },
        "message": {
            "from": from, "to": to, "value": value,
            "validAfter": valid_after, "validBefore": valid_before, "nonce": nonce
        }
    })
    .to_string()
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test panics on out-of-bounds are acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn typed_data_has_correct_structure() {
        let data = build_typed_data(
            "USD Coin", "2", "8453", "0xToken", "0xFrom", "0xTo", "100000", "0x0", "0x1", "0xnonce",
        );
        let v: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(v["primaryType"], "TransferWithAuthorization");
        assert_eq!(v["domain"]["name"], "USD Coin");
        assert_eq!(v["domain"]["chainId"], "8453");
        assert_eq!(v["message"]["from"], "0xFrom");
        assert_eq!(v["message"]["to"], "0xTo");
        assert_eq!(v["message"]["value"], "100000");
        assert!(v["types"]["EIP712Domain"].is_array());
        assert!(v["types"]["TransferWithAuthorization"].is_array());
    }
}
