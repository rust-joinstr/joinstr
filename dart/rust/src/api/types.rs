//! flutter_rust_bridge mirrors of the joinstr/bitcoin/nostr types.

use std::str::FromStr;

use joinstr::bip39::Mnemonic;
use joinstr::interface::{PeerConfig, PoolConfig};
use joinstr::joinstr::Step;
use joinstr::miniscript::bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TxOut, Txid,
};
use joinstr::nostr::{Fee, Pool, Timeline};
use joinstr::signer::{Coin, CoinPath};
use zeroize::Zeroizing;

use crate::api::error::JoinstrError;

pub enum BitcoinNetwork {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl From<BitcoinNetwork> for Network {
    fn from(value: BitcoinNetwork) -> Self {
        match value {
            BitcoinNetwork::Bitcoin => Network::Bitcoin,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Signet => Network::Signet,
            BitcoinNetwork::Regtest => Network::Regtest,
        }
    }
}

/// A spendable coin (UTXO). Round-trips losslessly back into a coinjoin input.
pub struct FfiCoin {
    pub txid: String,
    pub vout: u32,
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
    pub sequence: u32,
    pub coin_path_depth: u32,
    pub coin_path_index: Option<u32>,
}

impl From<Coin> for FfiCoin {
    fn from(coin: Coin) -> Self {
        FfiCoin {
            txid: coin.outpoint.txid.to_string(),
            vout: coin.outpoint.vout,
            value_sat: coin.txout.value.to_sat(),
            script_pubkey: coin.txout.script_pubkey.to_bytes(),
            sequence: coin.sequence.to_consensus_u32(),
            coin_path_depth: coin.coin_path.depth,
            coin_path_index: coin.coin_path.index,
        }
    }
}

impl TryFrom<FfiCoin> for Coin {
    type Error = JoinstrError;

    fn try_from(coin: FfiCoin) -> Result<Self, Self::Error> {
        let txid = Txid::from_str(&coin.txid)
            .map_err(|e| JoinstrError::new(format!("invalid txid `{}`: {e}", coin.txid)))?;
        Ok(Coin {
            txout: TxOut {
                value: Amount::from_sat(coin.value_sat),
                script_pubkey: ScriptBuf::from_bytes(coin.script_pubkey),
            },
            outpoint: OutPoint {
                txid,
                vout: coin.vout,
            },
            sequence: Sequence::from_consensus(coin.sequence),
            coin_path: CoinPath {
                depth: coin.coin_path_depth,
                index: coin.coin_path_index,
            },
        })
    }
}

/// Configuration for a coinjoin pool this peer initiates.
pub struct FfiPoolConfig {
    /// Denomination of each output, in BTC.
    pub denomination_btc: f64,
    /// Fee rate, in satoshis per vByte. Each output is reduced by `fee * 100`
    /// satoshis, 100 vB being the assumed weight of one participant's
    /// input+output pair.
    pub fee: u32,
    /// Seconds to wait for the pool to fill.
    pub max_duration: u64,
    /// Peers required before the coinjoin is built.
    pub peers: u32,
    pub network: BitcoinNetwork,
}

impl From<FfiPoolConfig> for PoolConfig {
    fn from(value: FfiPoolConfig) -> Self {
        PoolConfig {
            denomination: value.denomination_btc,
            fee: value.fee,
            max_duration: value.max_duration,
            peers: value.peers as usize,
            network: value.network.into(),
        }
    }
}

/// A single peer's coinjoin parameters.
pub struct FfiPeerConfig {
    /// BIP39 mnemonic of the wallet that owns `input` and will sign.
    pub mnemonic: String,
    /// Electrum server hostname / IP, without a port. Prefix with `ssl://` to
    /// negotiate TLS; anything else connects in plaintext.
    pub electrum_address: String,
    pub electrum_port: u16,
    /// The coin spent into the coinjoin (e.g. from `list_coins`).
    pub input: FfiCoin,
    /// Address that receives this peer's denominated output.
    pub output_address: String,
    /// Nostr relay url (`wss://` or `ws://`).
    pub relay: String,
    pub network: BitcoinNetwork,
    /// SOCKS5 proxy (`host:port`) for every relay and electrum connection this
    /// peer opens, e.g. a local Tor port such as `127.0.0.1:9050`. `None`
    /// connects directly. Each connection uses a fresh isolation credential so
    /// Tor assigns it its own circuit.
    pub proxy: Option<String>,
}

impl TryFrom<FfiPeerConfig> for PeerConfig {
    type Error = JoinstrError;

    fn try_from(mut value: FfiPeerConfig) -> Result<Self, Self::Error> {
        // Move the seed into a guard that wipes on every path out, including the
        // parse failure below. The parsed `Mnemonic` is what flows downstream.
        let mnemonic = Zeroizing::new(std::mem::take(&mut value.mnemonic));
        let mnemonics = Mnemonic::from_str(&mnemonic)
            .map_err(|e| JoinstrError::new(format!("invalid mnemonic: {e}")))?;
        let output = Address::from_str(&value.output_address)
            .map_err(|e| JoinstrError::new(format!("invalid output address: {e}")))?;
        let input = Coin::try_from(value.input)?;
        Ok(PeerConfig {
            mnemonics,
            electrum_address: value.electrum_address,
            electrum_port: value.electrum_port,
            input,
            output,
            relay: value.relay,
            network: value.network.into(),
            proxy: value.proxy,
        })
    }
}

impl FfiPeerConfig {
    pub(crate) fn native_network(&self) -> Network {
        match &self.network {
            BitcoinNetwork::Bitcoin => Network::Bitcoin,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Signet => Network::Signet,
            BitcoinNetwork::Regtest => Network::Regtest,
        }
    }
}

/// A coinjoin pool advertised on a nostr relay.
///
/// Pass `raw_json` back to `join_coinjoin` to join; the other fields are decoded
/// for display. There is deliberately no `network` field: pool events do not
/// carry one, so it cannot be known here. The caller supplies the network when
/// joining, via `FfiPeerConfig::network`.
pub struct FfiPool {
    pub id: String,
    /// Canonical JSON; pass back to `join_coinjoin`.
    pub raw_json: String,
    /// Denomination of each output, in satoshis.
    pub denomination_sat: u64,
    pub peers: u32,
    /// When the pool expires, as a unix timestamp in seconds. Pool events carry
    /// an absolute instant (`now + max_duration`), never a duration.
    pub expires_at_unix_sec: u64,
    pub relay: String,
    /// Fixed fee rate in satoshis per vByte. Pools that delegate their fee to a
    /// provider cannot be joined by this version and are never listed.
    pub fee_rate: u32,
    /// Initiator's nostr public key, as hex.
    pub public_key: String,
    pub version: Option<String>,
}

impl FfiPool {
    pub(crate) fn from_pool(pool: &Pool) -> Result<FfiPool, JoinstrError> {
        let raw_json = joinstr::serde_json::to_string(pool)
            .map_err(|e| JoinstrError::new(format!("failed to serialize pool: {e}")))?;

        // `payload` is `#[serde(flatten)]` into an `Option`, so serde yields
        // `None` rather than an error whenever any inner field fails to decode
        // (e.g. a fractional `fee_rate`, which `Fee::Fixed(u32)` cannot parse).
        // Reporting that as a zero-valued pool would render an unjoinable pool
        // as a plausible one, so refuse it instead.
        let payload = pool.payload.as_ref().ok_or_else(|| {
            JoinstrError::new(format!(
                "pool {} has no decodable payload; it may use fields this \
                 version cannot parse",
                pool.id
            ))
        })?;

        let denomination_sat = payload.denomination.to_sat();
        // `peers` is a relay-controlled `usize`. Truncating it would render a
        // pool that can never fill (`"peers": 4294967298`) as a plausible
        // 2-peer one, while `raw_json` still carries the real value into
        // `join_coinjoin`'s `min_peers`.
        let peers = u32::try_from(payload.peers).map_err(|_| {
            JoinstrError::new(format!(
                "pool {} requires {} peers, more than this version can join",
                pool.id, payload.peers
            ))
        })?;
        // Only `Simple` carries an absolute expiry; `Fixed` and `Timeout` carry
        // a `max_duration`. Rather than collapse both units into one field,
        // refuse them: `Joinstr::new_peer_with_electrum` rejects every non-`Simple`
        // timeline with `TimelineNotImplemented`, so such a pool can never be
        // joined and must not be listed as though it could be.
        let expires_at_unix_sec = match payload.timeout {
            Timeline::Simple(t) => t,
            _ => {
                return Err(JoinstrError::new(format!(
                    "pool {} uses a timeline this version cannot join",
                    pool.id
                )))
            }
        };
        let relay = payload.relay.clone();
        // As with the timeline above, `Joinstr::new_peer` rejects a provider fee
        // with `FeeProviderNotImplemented`. Reporting it as 0 sat/vB would list
        // an unjoinable pool as the cheapest one on offer.
        let fee_rate = match &payload.fee {
            Fee::Fixed(fee) => *fee,
            Fee::Provider(_) => {
                return Err(JoinstrError::new(format!(
                    "pool {} delegates its fee to a provider, which this \
                     version cannot join",
                    pool.id
                )))
            }
        };

        Ok(FfiPool {
            id: pool.id.clone(),
            raw_json,
            denomination_sat,
            peers,
            expires_at_unix_sec,
            relay,
            fee_rate,
            public_key: pool.public_key.to_string(),
            version: pool.version.clone(),
        })
    }
}

/// A coinjoin progress update, streamed to the caller as the round advances so
/// it can render a step-by-step timeline. A plain struct (not an enum with
/// data) so the bindings do not pull in `freezed`. `txid` is set on the
/// terminal `Done` step, `error` on the terminal `Failed` step.
pub struct FfiCoinjoinUpdate {
    pub step: FfiCoinjoinStep,
    pub txid: Option<String>,
    pub error: Option<String>,
}

/// The coinjoin steps worth showing in a timeline. `Done`/`Failed` are the two
/// terminal states the bindings synthesize; the crate's `Unconfigured`/
/// `Configured`/`Failed` bookkeeping states collapse to `Other`.
pub enum FfiCoinjoinStep {
    Connecting,
    Posting,
    OutputRegistration,
    InputRegistration,
    Broadcast,
    Mined,
    Done,
    Failed,
    Other,
}

impl From<Step> for FfiCoinjoinStep {
    fn from(step: Step) -> Self {
        match step {
            Step::Connecting => FfiCoinjoinStep::Connecting,
            Step::Posting => FfiCoinjoinStep::Posting,
            Step::OutputRegistration => FfiCoinjoinStep::OutputRegistration,
            Step::InputRegistration => FfiCoinjoinStep::InputRegistration,
            Step::Broadcast => FfiCoinjoinStep::Broadcast,
            Step::Mined => FfiCoinjoinStep::Mined,
            Step::Unconfigured | Step::Configured | Step::Failed => FfiCoinjoinStep::Other,
        }
    }
}

impl FfiCoinjoinUpdate {
    pub(crate) fn step(step: Step) -> Self {
        FfiCoinjoinUpdate {
            step: FfiCoinjoinStep::from(step),
            txid: None,
            error: None,
        }
    }

    pub(crate) fn done(txid: String) -> Self {
        FfiCoinjoinUpdate {
            step: FfiCoinjoinStep::Done,
            txid: Some(txid),
            error: None,
        }
    }

    pub(crate) fn failed(message: String) -> Self {
        FfiCoinjoinUpdate {
            step: FfiCoinjoinStep::Failed,
            txid: None,
            error: Some(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use joinstr::nostr::{PoolPayload, PoolType, Transport, Vpn};

    const PUBKEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn pool_with(payload: Option<PoolPayload>) -> Pool {
        Pool {
            version: Some("1".into()),
            id: "pool-id".into(),
            network: Network::Signet,
            pool_type: PoolType::Create,
            public_key: PUBKEY.parse().unwrap(),
            payload,
        }
    }

    fn payload_with(timeout: Timeline, fee: Fee) -> PoolPayload {
        PoolPayload {
            denomination: Amount::from_sat(100_000),
            peers: 2,
            timeout,
            relay: "wss://nos.lol".into(),
            fee,
            transport: Transport {
                vpn: Some(Vpn {
                    enable: false,
                    gateway: None,
                }),
                tor: None,
            },
            vpn_gateway: None,
        }
    }

    /// `Simple` carries an absolute unix timestamp, matching what the Electrum
    /// plugin writes (`int(time.time()) + timeout`) and what `Pool::create`
    /// builds. It is surfaced verbatim, not reinterpreted as a duration.
    #[test]
    fn simple_timeline_is_surfaced_as_an_absolute_expiry() {
        let expiry = 1_793_500_000;
        let pool = pool_with(Some(payload_with(Timeline::Simple(expiry), Fee::Fixed(1))));
        assert_eq!(
            FfiPool::from_pool(&pool).unwrap().expires_at_unix_sec,
            expiry
        );
    }

    /// `Joinstr::new_peer_with_electrum` rejects every non-`Simple` timeline
    /// with `TimelineNotImplemented`, so listing such a pool would offer the
    /// user a join that cannot succeed.
    #[test]
    fn unjoinable_timelines_are_refused_rather_than_listed() {
        for timeline in [
            Timeline::Fixed {
                start: 10,
                max_duration: 600,
            },
            Timeline::Timeout {
                timeout: 20,
                max_duration: 900,
            },
        ] {
            let pool = pool_with(Some(payload_with(timeline, Fee::Fixed(1))));
            let err = FfiPool::from_pool(&pool).err().unwrap();
            assert!(
                err.message.contains("cannot join"),
                "timeline {timeline:?}: {}",
                err.message
            );
        }
    }

    #[test]
    fn fixed_fee_is_passed_through() {
        let fixed = pool_with(Some(payload_with(Timeline::Simple(300), Fee::Fixed(7))));
        assert_eq!(FfiPool::from_pool(&fixed).unwrap().fee_rate, 7);
    }

    /// `Joinstr::new_peer` returns `FeeProviderNotImplemented` for these, so a
    /// provider-fee pool must not be listed as a joinable 0 sat/vB pool.
    #[test]
    fn provider_fee_is_refused_not_reported_as_zero() {
        let provider = pool_with(Some(payload_with(
            Timeline::Simple(300),
            Fee::Provider(joinstr::nostr::Provider {
                address: "provider.example".into(),
            }),
        )));
        let err = FfiPool::from_pool(&provider).err().unwrap();
        assert!(err.message.contains("provider"), "{}", err.message);
    }

    /// A relay-controlled `usize` must not truncate into `u32`.
    #[test]
    fn peer_count_above_u32_is_refused_not_truncated() {
        let mut payload = payload_with(Timeline::Simple(300), Fee::Fixed(1));
        payload.peers = u32::MAX as usize + 2; // would truncate to 1
        let err = FfiPool::from_pool(&pool_with(Some(payload))).err().unwrap();
        assert!(
            err.message.contains("more than this version"),
            "{}",
            err.message
        );
    }

    #[test]
    fn payload_fields_are_mapped() {
        let pool = pool_with(Some(payload_with(Timeline::Simple(300), Fee::Fixed(1))));
        let ffi = FfiPool::from_pool(&pool).unwrap();
        assert_eq!(ffi.denomination_sat, 100_000);
        assert_eq!(ffi.peers, 2);
        assert_eq!(ffi.relay, "wss://nos.lol");
        assert_eq!(ffi.id, "pool-id");
        assert_eq!(ffi.version.as_deref(), Some("1"));
    }

    fn peer_config_with(mnemonic: &str) -> FfiPeerConfig {
        FfiPeerConfig {
            mnemonic: mnemonic.into(),
            electrum_address: "127.0.0.1".into(),
            electrum_port: 50001,
            input: FfiCoin {
                txid: "0000000000000000000000000000000000000000000000000000000000000001".into(),
                vout: 0,
                value_sat: 100_500,
                script_pubkey: vec![0x00, 0x14],
                sequence: 0xffff_ffff,
                coin_path_depth: 0,
                coin_path_index: Some(0),
            },
            output_address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            relay: "wss://nos.lol".into(),
            network: BitcoinNetwork::Regtest,
            proxy: None,
        }
    }

    /// The mnemonic is moved into a `Zeroizing` guard *before* the parse, so
    /// this error path wipes it rather than dropping the seed intact.
    #[test]
    fn invalid_mnemonic_is_rejected() {
        let err = PeerConfig::try_from(peer_config_with("not a real mnemonic"))
            .err()
            .unwrap();
        assert!(err.message.contains("invalid mnemonic"), "{}", err.message);
    }

    #[test]
    fn valid_peer_config_converts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        assert!(PeerConfig::try_from(peer_config_with(mnemonic)).is_ok());
    }

    #[test]
    fn missing_payload_is_an_error_not_a_zeroed_pool() {
        let err = FfiPool::from_pool(&pool_with(None)).err().unwrap();
        assert!(
            err.message.contains("no decodable payload"),
            "{}",
            err.message
        );
    }

    /// The Electrum plugin publishes `fee_rate` as a float (`fee_per_kb/1000`),
    /// which `Fee::Fixed(u32)` cannot parse. Because `payload` is a flattened
    /// `Option`, serde reports that as `None` instead of an error. Pin both
    /// halves: the silent `None`, and our refusal to render it as a real pool.
    #[test]
    fn float_fee_rate_yields_no_payload_and_is_rejected() {
        let json = r#"{"type":"new_pool","id":"abc",
            "public_key":"0000000000000000000000000000000000000000000000000000000000000001",
            "denomination":0.001,"peers":2,"timeout":300,"relay":"wss://nos.lol",
            "fee_rate":1.5,"transport":"vpn"}"#;
        let pool: Pool = joinstr::serde_json::from_str(json).unwrap();
        assert!(pool.payload.is_none(), "serde silently drops the payload");
        assert!(FfiPool::from_pool(&pool).is_err());

        // The same pool with an integer fee_rate decodes normally.
        let pool: Pool = joinstr::serde_json::from_str(&json.replace("1.5", "1")).unwrap();
        assert_eq!(FfiPool::from_pool(&pool).unwrap().fee_rate, 1);
    }

    /// `raw_json` is fed straight back into `join_coinjoin`, so every field that
    /// determines join behaviour must survive the round trip.
    ///
    /// Two fields are exempt by design: `network` is `skip_serializing` (the
    /// peer reapplies it), and `transport` encodes to a bare `"tor"`/`"vpn"`/`""`
    /// string, so an absent leg decodes back as an explicitly-disabled one.
    #[test]
    fn raw_json_round_trips_the_fields_that_drive_the_join() {
        let pool = pool_with(Some(payload_with(Timeline::Simple(300), Fee::Fixed(1))));
        let ffi = FfiPool::from_pool(&pool).unwrap();
        let decoded: Pool = joinstr::serde_json::from_str(&ffi.raw_json).unwrap();

        assert_eq!(decoded.id, pool.id);
        assert_eq!(decoded.public_key, pool.public_key);
        assert_eq!(decoded.version, pool.version);
        assert_eq!(decoded.pool_type, pool.pool_type);

        let (got, want) = (decoded.payload.unwrap(), pool.payload.unwrap());
        assert_eq!(got.denomination, want.denomination);
        assert_eq!(got.peers, want.peers);
        assert_eq!(got.timeout, want.timeout);
        assert_eq!(got.relay, want.relay);
        assert_eq!(got.fee, want.fee);
        assert!(!got.transport.tor.is_some_and(|t| t.enable));
        assert!(!got.transport.vpn.is_some_and(|v| v.enable));
    }
}
