//! The four joinstr operations exposed to Dart. These wrap
//! [`joinstr::interface`] and are blocking; flutter_rust_bridge runs them off
//! the UI isolate so Dart awaits each as a `Future`.

use joinstr::interface;
use joinstr::nostr::Pool;

use crate::api::error::JoinstrError;
use crate::api::types::{BitcoinNetwork, FfiCoin, FfiPeerConfig, FfiPool, FfiPoolConfig};

/// Upper bound on the number of derivation indexes a single `list_coins` call
/// may scan. Each index issues two synchronous electrum queries, so an
/// unbounded span (e.g. `0..u32::MAX`) would hang the caller indefinitely.
const MAX_SCAN_SPAN: u32 = 100_000;

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
    let coins = interface::list_coins(
        mnemonic,
        electrum_address,
        electrum_port,
        (range_start, range_end),
        network.into(),
    )?;
    Ok(coins.into_iter().map(FfiCoin::from).collect())
}

/// List coinjoin pools advertised on `relay` (`wss://`/`ws://`) within the last
/// `back` seconds, waiting `timeout` microseconds for relay notifications.
pub fn list_pools(back: u64, timeout: u64, relay: String) -> Result<Vec<FfiPool>, JoinstrError> {
    let pools = interface::list_pools(back, timeout, relay)?;
    pools.iter().map(FfiPool::from_pool).collect()
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
pub fn join_coinjoin(
    pool_raw_json: String,
    peer: FfiPeerConfig,
) -> Result<String, JoinstrError> {
    let mut pool: Pool = joinstr::serde_json::from_str(&pool_raw_json)
        .map_err(|e| JoinstrError::new(format!("invalid pool json: {e}")))?;
    // `Pool::network` is `#[serde(skip_serializing)]` and defaults to mainnet on
    // decode, so reapply the network the peer is actually operating on.
    pool.network = peer.native_network();

    let peer_config = peer.try_into()?;
    let txid = interface::join_coinjoin(pool, peer_config)?;
    Ok(txid)
}
