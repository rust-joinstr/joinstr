//! The four joinstr operations exposed to Dart. These wrap
//! [`joinstr::interface`] and are blocking; flutter_rust_bridge runs them off
//! the UI isolate so Dart awaits each as a `Future`.

use joinstr::interface;
use joinstr::log::warn;
use joinstr::nostr::Pool;
use zeroize::Zeroizing;

use crate::api::error::JoinstrError;
use crate::api::types::{BitcoinNetwork, FfiCoin, FfiPeerConfig, FfiPool, FfiPoolConfig};

/// Upper bound on the number of derivation indexes a single `list_coins` call
/// may scan. Each index issues two synchronous electrum queries, so an
/// unbounded span (e.g. `0..u32::MAX`) would hang the caller indefinitely.
const MAX_SCAN_SPAN: u32 = 100_000;

/// Reject inverted and oversized scan ranges before they reach electrum.
fn check_scan_range(range_start: u32, range_end: u32) -> Result<(), JoinstrError> {
    if range_end < range_start {
        return Err(JoinstrError::new(format!(
            "invalid range: end {range_end} is before start {range_start}"
        )));
    }
    if range_end - range_start > MAX_SCAN_SPAN {
        return Err(JoinstrError::new(format!(
            "range span {} exceeds maximum {MAX_SCAN_SPAN}",
            range_end - range_start
        )));
    }
    Ok(())
}

/// List spendable coins by scanning electrum over derivation indexes
/// `[range_start, range_end)` on both the receive and change branches.
pub fn list_coins(
    mnemonic: String,
    electrum_address: String,
    electrum_port: u16,
    range_start: u32,
    range_end: u32,
    network: BitcoinNetwork,
) -> Result<Vec<FfiCoin>, JoinstrError> {
    // Wipe our owned copy of the seed on every path out, including the `?`
    // early returns below.
    let mnemonic = Zeroizing::new(mnemonic);
    check_scan_range(range_start, range_end)?;
    let coins = interface::list_coins(
        &mnemonic,
        electrum_address,
        electrum_port,
        (range_start, range_end),
        network.into(),
    )?;
    Ok(coins.into_iter().map(FfiCoin::from).collect())
}

/// List coinjoin pools advertised on `relay` (`wss://`/`ws://`) within the last
/// `back` seconds, waiting `timeout` microseconds for relay notifications.
///
/// A relay carries pools from every client; one this version cannot decode is
/// skipped, not surfaced as a placeholder and not allowed to fail the listing.
pub fn list_pools(back: u64, timeout: u64, relay: String) -> Result<Vec<FfiPool>, JoinstrError> {
    let pools = interface::list_pools(back, timeout, relay)?;
    Ok(pools
        .iter()
        .filter_map(|pool| match FfiPool::from_pool(pool) {
            Ok(ffi) => Some(ffi),
            Err(e) => {
                warn!("skipping undecodable pool: {}", e.message);
                None
            }
        })
        .collect())
}

/// Initiate a new coinjoin pool and participate in it.
///
/// Blocks until the pool fills and the coinjoin transaction is built and
/// broadcast, then returns its txid (hex). Returns an error if the pool times
/// out before enough peers join.
pub fn initiate_coinjoin(
    config: FfiPoolConfig,
    peer: FfiPeerConfig,
) -> Result<String, JoinstrError> {
    let pool_config = config.into();
    let peer_config = peer.try_into()?;
    let txid = interface::initiate_coinjoin(pool_config, peer_config)?;
    Ok(txid.to_string())
}

/// Join an advertised pool, passing the `raw_json` of an [`FfiPool`] from
/// [`list_pools`]. Blocks until the coinjoin is broadcast; returns its txid.
pub fn join_coinjoin(pool_raw_json: String, peer: FfiPeerConfig) -> Result<String, JoinstrError> {
    let mut pool: Pool = joinstr::serde_json::from_str(&pool_raw_json)
        .map_err(|e| JoinstrError::new(format!("invalid pool json: {e}")))?;
    // `Pool::network` is `#[serde(skip_serializing)]` and defaults to mainnet on
    // decode, so reapply the network the peer is actually operating on.
    pool.network = peer.native_network();

    let peer_config = peer.try_into()?;
    let txid = interface::join_coinjoin(pool, peer_config)?;
    Ok(txid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_range_accepts_empty_and_max_span() {
        assert!(check_scan_range(0, 0).is_ok());
        assert!(check_scan_range(5, 6).is_ok());
        assert!(check_scan_range(0, MAX_SCAN_SPAN).is_ok());
        // The bound is on the span, not on the absolute indexes.
        assert!(check_scan_range(u32::MAX - MAX_SCAN_SPAN, u32::MAX).is_ok());
    }

    #[test]
    fn scan_range_rejects_span_over_max() {
        let err = check_scan_range(0, MAX_SCAN_SPAN + 1).unwrap_err();
        assert!(err.message.contains("exceeds maximum"), "{}", err.message);
    }

    #[test]
    fn scan_range_rejects_inverted_range() {
        let err = check_scan_range(10, 9).unwrap_err();
        assert!(err.message.contains("is before start"), "{}", err.message);
    }

    /// An inverted range must be rejected before the span subtraction, which
    /// would otherwise underflow (panic in debug, wrap in release).
    #[test]
    fn scan_range_inverted_does_not_underflow() {
        let err = check_scan_range(u32::MAX, 0).unwrap_err();
        assert!(err.message.contains("is before start"), "{}", err.message);
    }
}
