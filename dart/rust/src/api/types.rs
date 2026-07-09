//! flutter_rust_bridge mirrors of the joinstr/bitcoin/nostr types.

use std::str::FromStr;

use joinstr::bip39::Mnemonic;
use joinstr::interface::{PeerConfig, PoolConfig};
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
    /// Pool timeout / max duration, in seconds.
    pub timeout: u64,
    pub relay: String,
    /// Fixed fee rate in satoshis per vByte (0 when delegated to a provider).
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
        let peers = payload.peers as u32;
        let timeout = match payload.timeout {
            Timeline::Simple(t) => t,
            Timeline::Fixed { max_duration, .. } => max_duration,
            Timeline::Timeout { max_duration, .. } => max_duration,
        };
        let relay = payload.relay.clone();
        let fee_rate = match &payload.fee {
            Fee::Fixed(fee) => *fee,
            Fee::Provider(_) => 0,
        };

        Ok(FfiPool {
            id: pool.id.clone(),
            raw_json,
            denomination_sat,
            peers,
            timeout,
            relay,
            fee_rate,
            public_key: pool.public_key.to_string(),
            version: pool.version.clone(),
        })
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

    #[test]
    fn timeline_variants_all_map_to_max_duration() {
        let cases = [
            (Timeline::Simple(300), 300),
            (
                Timeline::Fixed {
                    start: 10,
                    max_duration: 600,
                },
                600,
            ),
            (
                Timeline::Timeout {
                    timeout: 20,
                    max_duration: 900,
                },
                900,
            ),
        ];
        for (timeline, expected) in cases {
            let pool = pool_with(Some(payload_with(timeline, Fee::Fixed(1))));
            let ffi = FfiPool::from_pool(&pool).unwrap();
            assert_eq!(ffi.timeout, expected, "timeline {timeline:?}");
        }
    }

    #[test]
    fn fixed_fee_is_passed_through_and_provider_fee_is_zero() {
        let fixed = pool_with(Some(payload_with(Timeline::Simple(300), Fee::Fixed(7))));
        assert_eq!(FfiPool::from_pool(&fixed).unwrap().fee_rate, 7);

        let provider = pool_with(Some(payload_with(
            Timeline::Simple(300),
            Fee::Provider(joinstr::nostr::Provider {
                address: "provider.example".into(),
            }),
        )));
        assert_eq!(FfiPool::from_pool(&provider).unwrap().fee_rate, 0);
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
