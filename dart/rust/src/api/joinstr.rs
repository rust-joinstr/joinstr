//! The four joinstr operations exposed to Dart. These wrap
//! [`joinstr::interface`] and are blocking; flutter_rust_bridge runs them off
//! the UI isolate so Dart awaits each as a `Future`.

use std::sync::Mutex;

use crate::frb_generated::StreamSink;
use joinstr::interface;
use joinstr::joinstr::CoinjoinProgress;
use joinstr::log::warn;
use joinstr::nostr::Pool;
use zeroize::Zeroizing;

use crate::api::error::JoinstrError;
use crate::api::types::{
    BitcoinNetwork, FfiCoin, FfiCoinjoinUpdate, FfiPeerConfig, FfiPool, FfiPoolConfig,
};

/// List spendable coins by scanning electrum over derivation indexes
/// `[range_start, range_end)` on both the receive and change branches.
///
/// The range is bounded by `interface::check_scan_range`, so every binding
/// shares one guard rather than each re-implementing it.
pub fn list_coins(
    mnemonic: String,
    electrum_address: String,
    electrum_port: u16,
    range_start: u32,
    range_end: u32,
    network: BitcoinNetwork,
    proxy: Option<String>,
) -> Result<Vec<FfiCoin>, JoinstrError> {
    // Wipe our owned copy of the seed on every path out, including the `?`
    // early returns below.
    let mnemonic = Zeroizing::new(mnemonic);
    let coins = interface::list_coins(
        &mnemonic,
        electrum_address,
        electrum_port,
        (range_start, range_end),
        network.into(),
        proxy,
    )?;
    Ok(coins.into_iter().map(FfiCoin::from).collect())
}

/// List coinjoin pools advertised on `relay` (`wss://`/`ws://`) within the last
/// `back` seconds, waiting `timeout` microseconds for relay notifications.
///
/// `proxy` is an optional SOCKS5 address (`host:port`, e.g. a local Tor port)
/// the relay is reached through; `None` connects directly.
///
/// A relay carries pools from every client; one this version cannot decode is
/// skipped, not surfaced as a placeholder and not allowed to fail the listing.
pub fn list_pools(
    back: u64,
    timeout: u64,
    relay: String,
    proxy: Option<String>,
) -> Result<Vec<FfiPool>, JoinstrError> {
    let pools = interface::list_pools(back, timeout, relay, proxy)?;
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
    progress: StreamSink<FfiCoinjoinUpdate>,
) -> Result<(), JoinstrError> {
    let pool_config = config.into();
    let peer_config = peer.try_into()?;
    // Remember the latest progress so the terminal update can carry the detail
    // gathered during the round rather than nulling it out.
    let last: Mutex<Option<CoinjoinProgress>> = Mutex::new(None);
    let on_step = |p: CoinjoinProgress| {
        *last.lock().expect("poisoned") = Some(p.clone());
        let _ = progress.add(FfiCoinjoinUpdate::progress(p));
    };
    match interface::initiate_coinjoin_with_progress(pool_config, peer_config, on_step) {
        Ok(txid) => {
            let detail = last.lock().expect("poisoned").clone();
            let _ = progress.add(FfiCoinjoinUpdate::done(txid.to_string(), detail));
            Ok(())
        }
        Err(e) => {
            let detail = last.lock().expect("poisoned").clone();
            let _ = progress.add(FfiCoinjoinUpdate::failed(e.to_string(), detail));
            // Also fail the call: pushing to the sink is best effort (a cancelled
            // Dart subscription silently drops it), so returning Ok would report
            // a failed coinjoin as a success.
            Err(JoinstrError::new(e.to_string()))
        }
    }
}

/// Join an advertised pool, passing the `raw_json` of an [`FfiPool`] from
/// [`list_pools`]. Blocks until the coinjoin is broadcast; returns its txid.
pub fn join_coinjoin(
    pool_raw_json: String,
    peer: FfiPeerConfig,
    progress: StreamSink<FfiCoinjoinUpdate>,
) -> Result<(), JoinstrError> {
    let mut pool: Pool = joinstr::serde_json::from_str(&pool_raw_json)
        .map_err(|e| JoinstrError::new(format!("invalid pool json: {e}")))?;
    // `Pool::network` is `#[serde(skip_serializing)]` and defaults to mainnet on
    // decode, so reapply the network the peer is actually operating on.
    pool.network = peer.native_network();

    let peer_config = peer.try_into()?;
    let last: Mutex<Option<CoinjoinProgress>> = Mutex::new(None);
    let on_step = |p: CoinjoinProgress| {
        *last.lock().expect("poisoned") = Some(p.clone());
        let _ = progress.add(FfiCoinjoinUpdate::progress(p));
    };
    match interface::join_coinjoin_with_progress(pool, peer_config, on_step) {
        Ok(txid) => {
            let detail = last.lock().expect("poisoned").clone();
            let _ = progress.add(FfiCoinjoinUpdate::done(txid, detail));
            Ok(())
        }
        Err(e) => {
            let detail = last.lock().expect("poisoned").clone();
            let _ = progress.add(FfiCoinjoinUpdate::failed(e.to_string(), detail));
            Err(JoinstrError::new(e.to_string()))
        }
    }
}
