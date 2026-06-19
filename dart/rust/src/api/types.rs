//! flutter_rust_bridge mirrors of the joinstr/bitcoin/nostr types.

use std::str::FromStr;

use joinstr::bip39::Mnemonic;
use joinstr::interface::{PeerConfig, PoolConfig};
use joinstr::miniscript::bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TxOut, Txid,
};
use joinstr::nostr::{Fee, Pool, Timeline};
use joinstr::signer::{Coin, CoinPath};
use zeroize::Zeroize;

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

impl From<Network> for BitcoinNetwork {
    fn from(value: Network) -> Self {
        match value {
            Network::Bitcoin => BitcoinNetwork::Bitcoin,
            Network::Testnet => BitcoinNetwork::Testnet,
            Network::Signet => BitcoinNetwork::Signet,
            Network::Regtest => BitcoinNetwork::Regtest,
            // bitcoin::Network is #[non_exhaustive]
            _ => BitcoinNetwork::Regtest,
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
    /// Mining fee contributed, in satoshis.
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
    /// Electrum server hostname / IP (no scheme, no port).
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
        let mnemonics = Mnemonic::from_str(&value.mnemonic)
            .map_err(|e| JoinstrError::new(format!("invalid mnemonic: {e}")))?;
        // Wipe our owned copy of the seed once it has been parsed; the parsed
        // `Mnemonic` is what flows downstream.
        value.mnemonic.zeroize();
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
/// for display.
pub struct FfiPool {
    pub id: String,
    /// Canonical JSON; pass back to `join_coinjoin`.
    pub raw_json: String,
    pub network: BitcoinNetwork,
    /// Denomination of each output, in satoshis.
    pub denomination_sat: u64,
    pub peers: u32,
    /// Pool timeout / max duration, in seconds.
    pub timeout: u64,
    pub relay: String,
    /// Fixed fee in satoshis (0 when delegated to a provider).
    pub fee_rate: u32,
    /// Initiator's nostr public key, as hex.
    pub public_key: String,
    pub version: Option<String>,
}

impl FfiPool {
    pub(crate) fn from_pool(pool: &Pool) -> Result<FfiPool, JoinstrError> {
        let raw_json = joinstr::serde_json::to_string(pool)
            .map_err(|e| JoinstrError::new(format!("failed to serialize pool: {e}")))?;

        let (denomination_sat, peers, timeout, relay, fee_rate) = match &pool.payload {
            Some(payload) => (
                payload.denomination.to_sat(),
                payload.peers as u32,
                match payload.timeout {
                    Timeline::Simple(t) => t,
                    Timeline::Fixed { max_duration, .. } => max_duration,
                    Timeline::Timeout { max_duration, .. } => max_duration,
                },
                payload.relay.clone(),
                match &payload.fee {
                    Fee::Fixed(fee) => *fee,
                    Fee::Provider(_) => 0,
                },
            ),
            None => (0, 0, 0, String::new(), 0),
        };

        Ok(FfiPool {
            id: pool.id.clone(),
            raw_json,
            network: pool.network.into(),
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
