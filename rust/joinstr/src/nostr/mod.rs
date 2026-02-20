#[cfg(feature = "async")]
pub mod r#async;
pub mod error;
pub mod sync;

use bip39::serde::{Deserialize, Serialize};
use bitcoin::{hashes::sha256, Address};
use hex_conservative::DisplayHex;
use miniscript::bitcoin::{
    address::NetworkUnchecked,
    consensus::encode::{deserialize_hex, serialize_hex},
    Amount, Network, Psbt, Transaction, TxIn,
};
use nostr::hashes::{Hash, HashEngine};
use nostr::PublicKey;
use serde::Serializer;
use serde_json::{Map, Value};
use simple_nostr_client::nostr::{
    self,
    event::{Event, EventBuilder, Kind},
};
use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputDataSigned {
    pub txin: TxIn,
    pub amount: Option<Amount>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    NoInput,
    TooMuchInputs,
    WitnessMissing,
}

impl TryFrom<Psbt> for InputDataSigned {
    type Error = Error;

    fn try_from(value: Psbt) -> Result<Self, Self::Error> {
        match value.inputs.len() {
            0 => return Err(Error::NoInput),
            i if i > 1 => return Err(Error::TooMuchInputs),
            _ => {}
        }
        match value.unsigned_tx.input.len() {
            0 => return Err(Error::NoInput),
            i if i > 1 => return Err(Error::TooMuchInputs),
            _ => {}
        }

        let mut txin = value.unsigned_tx.input[0].to_owned();
        let psbt_input = &value.inputs[0];

        if txin.witness.is_empty() {
            if let Some(witness) = &psbt_input.final_script_witness {
                txin.witness = witness.clone();
            } else if !psbt_input.partial_sigs.is_empty() {
                let (pubkey, sig) = psbt_input.partial_sigs.iter().next().unwrap();
                let mut witness = miniscript::bitcoin::Witness::new();
                witness.push(sig.serialize());
                witness.push(pubkey.to_bytes());
                txin.witness = witness;
            } else {
                return Err(Error::WitnessMissing);
            }
        }
        let amount = psbt_input.witness_utxo.as_ref().map(|utxo| utxo.value);
        Ok(InputDataSigned { txin, amount })
    }
}

mod serde_denomination {
    use miniscript::bitcoin::Amount;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(amount: &Amount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(amount.to_btc())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Amount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match &value {
            serde_json::Value::Number(n) => {
                if n.is_f64() {
                    Amount::from_btc(n.as_f64().unwrap()).map_err(serde::de::Error::custom)
                } else if let Some(i) = n.as_u64() {
                    Ok(Amount::from_sat(i))
                } else {
                    Err(serde::de::Error::custom("invalid denomination"))
                }
            }
            _ => Err(serde::de::Error::custom("denomination must be a number")),
        }
    }
}

mod serde_relay {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(relay: &String, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(relay)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => Ok(s),
            serde_json::Value::Array(arr) => {
                if arr.is_empty() {
                    return Ok(String::new());
                }
                // Leniently picks the first string entry; non-string elements
                // are ignored to tolerate mixed-type arrays from other implementations.
                let first = arr.into_iter().find_map(|v| {
                    if let serde_json::Value::String(s) = v {
                        Some(s)
                    } else {
                        None
                    }
                });
                first.ok_or_else(|| {
                    serde::de::Error::custom("relay array contains no string entries")
                })
            }
            _ => Err(serde::de::Error::custom("relay must be a string or array")),
        }
    }
}

mod serde_transport {
    use super::{Tor, Transport, Vpn};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(transport: &Transport, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if transport.tor.as_ref().map_or(false, |t| t.enable) {
            serializer.serialize_str("tor")
        } else if transport.vpn.as_ref().map_or(false, |v| v.enable) {
            serializer.serialize_str("vpn")
        } else {
            serializer.serialize_str("")
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Transport, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "tor" => Ok(Transport {
                    vpn: Some(Vpn {
                        enable: false,
                        gateway: None,
                    }),
                    tor: Some(Tor { enable: true }),
                }),
                "vpn" => Ok(Transport {
                    vpn: Some(Vpn {
                        enable: true,
                        gateway: None,
                    }),
                    tor: Some(Tor { enable: false }),
                }),
                _ => Ok(Transport {
                    vpn: Some(Vpn {
                        enable: false,
                        gateway: None,
                    }),
                    tor: Some(Tor { enable: false }),
                }),
            },
            serde_json::Value::Object(_) => {
                let t: TransportObject =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(Transport {
                    vpn: t.vpn,
                    tor: t.tor,
                })
            }
            _ => Err(serde::de::Error::custom(
                "transport must be a string or object",
            )),
        }
    }

    #[derive(serde::Deserialize)]
    struct TransportObject {
        vpn: Option<Vpn>,
        tor: Option<Tor>,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pool {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default = "default_version")]
    #[serde(alias = "versions")]
    pub version: Option<String>,
    pub id: String,
    #[serde(default = "default_network")]
    #[serde(skip_serializing)]
    pub network: Network,
    #[serde(rename = "type")]
    pub pool_type: PoolType,
    #[serde(alias = "publicKey")]
    pub public_key: nostr::PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub payload: Option<PoolPayload>,
}

impl Pool {
    pub fn create(
        relay: String,
        denomination: u64,
        peers: usize,
        timeout: u64,
        fee: u32,
        network: bitcoin::Network,
        key: PublicKey,
    ) -> Pool {
        let timeout = SystemTime::now()
            .checked_add(Duration::from_secs(timeout))
            .expect("valid timestamp")
            .duration_since(UNIX_EPOCH)
            .expect("valid timestamp")
            .as_secs();

        let payload = PoolPayload {
            denomination: bitcoin::Amount::from_sat(denomination),
            peers,
            timeout: Timeline::Simple(timeout),
            relay,
            fee: Fee::Fixed(fee),
            transport: default_transport(),
            vpn_gateway: None,
        };

        let id = pool_id(&key);

        Self {
            version: default_version(),
            id,
            network,
            pool_type: PoolType::Create,
            public_key: key,
            payload: Some(payload),
        }
    }
}

#[derive(Debug)]
pub enum EventError {
    ContentError,
    WrongKind,
    Parsing(ParsingError),
}

impl From<ParsingError> for EventError {
    fn from(value: ParsingError) -> Self {
        EventError::Parsing(value)
    }
}

impl TryFrom<Pool> for EventBuilder {
    type Error = EventError;
    fn try_from(value: Pool) -> Result<Self, EventError> {
        if let Ok(content) = serde_json::to_string(&value) {
            Ok(EventBuilder::new(Kind::Custom(2022), content, Vec::new()))
        } else {
            Err(EventError::ContentError)
        }
    }
}

impl TryFrom<Event> for Pool {
    type Error = EventError;

    fn try_from(event: Event) -> Result<Self, Self::Error> {
        if event.kind == Kind::Custom(2022) {
            serde_json::from_str(&event.content).map_err(|e| EventError::Parsing(e.into()))
        } else {
            Err(EventError::WrongKind)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PoolType {
    #[serde(rename = "new_pool", alias = "create")]
    Create,
    #[serde(rename = "update")]
    Update,
    #[serde(rename = "delete")]
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoolPayload {
    #[serde(with = "serde_denomination")]
    pub denomination: Amount,
    pub peers: usize,
    pub timeout: Timeline,
    #[serde(with = "serde_relay", alias = "relays")]
    pub relay: String,
    #[serde(rename = "fee_rate", alias = "feeRate")]
    pub fee: Fee,
    #[serde(with = "serde_transport")]
    pub transport: Transport,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "vpnGateway")]
    pub vpn_gateway: Option<String>,
}

pub fn default_version() -> Option<String> {
    Some("1".into())
}

fn default_network() -> Network {
    Network::Bitcoin
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum Timeline {
    Simple(u64),
    Fixed { start: u64, max_duration: u64 },
    Timeout { timeout: u64, max_duration: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum Fee {
    Fixed(u32),
    Provider(Provider),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Provider {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Transport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpn: Option<Vpn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor: Option<Tor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Vpn {
    pub enable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Tor {
    pub enable: bool,
}

#[derive(Debug, PartialEq)]
pub enum PoolMessage {
    Input(InputDataSigned),
    Output(miniscript::bitcoin::Address<NetworkUnchecked>),
    Psbt(Psbt),
    Transaction(Transaction),
    Join(Option<nostr::PublicKey>),
    Credentials(Credentials),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Credentials {
    pub id: String,
    #[serde(alias = "key", alias = "privateKey")]
    #[serde(serialize_with = "serialize_key")]
    pub private_key: nostr::SecretKey,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "publicKey")]
    pub public_key: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_denomination_opt")]
    pub denomination: Option<Amount>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<usize>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "feeRate")]
    pub fee_rate: Option<u32>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "vpnGateway")]
    pub vpn_gateway: Option<String>,
}

mod serde_denomination_opt {
    use miniscript::bitcoin::Amount;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(amount: &Option<Amount>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match amount {
            Some(a) => serializer.serialize_f64(a.to_btc()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Amount>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
        match value {
            None => Ok(None),
            Some(serde_json::Value::Number(n)) => {
                if n.is_f64() {
                    Ok(Some(
                        Amount::from_btc(n.as_f64().unwrap()).map_err(serde::de::Error::custom)?,
                    ))
                } else if let Some(i) = n.as_u64() {
                    Ok(Some(Amount::from_sat(i)))
                } else {
                    Err(serde::de::Error::custom("invalid denomination"))
                }
            }
            Some(serde_json::Value::Null) => Ok(None),
            _ => Err(serde::de::Error::custom("denomination must be a number")),
        }
    }
}

pub fn serialize_key<S>(key: &nostr::SecretKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let str = key.secret_bytes().to_lower_hex_string();
    serializer.serialize_str(&str)
}

#[derive(Debug)]
pub enum ParsingError {
    SerdeJson(serde_json::Error),
    Unknown,
    UnknownType(String),
    Input,
    Output,
    Psbt,
    Inputs,
    Outputs,
    Transaction,
    Join,
    NotAnObject,
    NotAnArray,
    MissingKey(String),
    WrongValue(String),
    Consensus,
    Credential,
    VersionNotSupported(String),
    Base64,
}

impl From<serde_json::Error> for ParsingError {
    fn from(value: serde_json::Error) -> Self {
        ParsingError::SerdeJson(value)
    }
}

impl FromStr for PoolMessage {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, ParsingError> {
        let json: Value = serde_json::from_str(s)?;
        if let Value::Object(map) = json {
            // version field is optional (Python doesn't send it)
            if let Some(Value::String(v)) = map.get("version") {
                if v != "1" {
                    return Err(ParsingError::VersionNotSupported(v.into()));
                }
            }

            if let Some(Value::String(t)) = map.get("type") {
                return match t.as_str() {
                    "psbt" => {
                        if let Some(Value::String(psbt_b64)) = map.get("psbt") {
                            let psbt_bytes = base64ct::Base64::decode_vec(psbt_b64)
                                .map_err(|_| ParsingError::Base64)?;
                            let psbt =
                                Psbt::deserialize(&psbt_bytes).map_err(|_| ParsingError::Psbt)?;
                            Ok(Self::Psbt(psbt))
                        } else {
                            Err(ParsingError::Psbt)
                        }
                    }
                    "input" => {
                        // Python sends {"psbt": "<base64>", "type": "input"}
                        // Some implementations use "hex" instead of "psbt"
                        let psbt_field = map
                            .get("psbt")
                            .or_else(|| map.get("hex"))
                            .and_then(|v| v.as_str());
                        if let Some(psbt_b64) = psbt_field {
                            let psbt_bytes = base64ct::Base64::decode_vec(psbt_b64)
                                .map_err(|_| ParsingError::Base64)?;
                            let psbt: Psbt =
                                Psbt::deserialize(&psbt_bytes).map_err(|_| ParsingError::Psbt)?;
                            let input: InputDataSigned =
                                psbt.try_into().map_err(|_| ParsingError::Input)?;
                            Ok(Self::Input(input))
                        } else if let Some(m) = map.get("input") {
                            if let Some(psbt_b64) = m.get("psbt").and_then(|v| v.as_str()) {
                                let psbt_bytes = base64ct::Base64::decode_vec(psbt_b64)
                                    .map_err(|_| ParsingError::Base64)?;
                                let psbt: Psbt = Psbt::deserialize(&psbt_bytes)
                                    .map_err(|_| ParsingError::Psbt)?;
                                let input: InputDataSigned =
                                    psbt.try_into().map_err(|_| ParsingError::Input)?;
                                Ok(Self::Input(input))
                            } else {
                                let input = InputDataSigned::from_value(m.clone())?;
                                Ok(Self::Input(input))
                            }
                        } else {
                            Err(ParsingError::Input)
                        }
                    }
                    "inputs" => {
                        if let Some(Value::Array(arr)) = map.get("inputs") {
                            if arr.len() != 1 {
                                return Err(ParsingError::Inputs);
                            }
                            let input = InputDataSigned::from_value(arr[0].clone())?;
                            Ok(Self::Input(input))
                        } else {
                            Err(ParsingError::Inputs)
                        }
                    }
                    "output" => {
                        if let Some(Value::String(addr)) = map.get("address") {
                            let addr: miniscript::bitcoin::Address<NetworkUnchecked> =
                                Address::from_str(addr).map_err(|_| ParsingError::Output)?;
                            Ok(Self::Output(addr))
                        } else {
                            Err(ParsingError::Output)
                        }
                    }
                    "outputs" => {
                        if let Some(Value::Array(arr)) = map.get("outputs") {
                            if arr.len() != 1 {
                                return Err(ParsingError::Outputs);
                            }
                            if let Some(addr_str) = arr[0].as_str() {
                                let addr: miniscript::bitcoin::Address<NetworkUnchecked> =
                                    Address::from_str(addr_str)
                                        .map_err(|_| ParsingError::Output)?;
                                Ok(Self::Output(addr))
                            } else {
                                Err(ParsingError::Output)
                            }
                        } else {
                            Err(ParsingError::Outputs)
                        }
                    }
                    "transaction" => {
                        if let Some(Value::String(s)) = map.get("transaction") {
                            let tx: Result<Transaction, _> = deserialize_hex(s);
                            return if let Ok(tx) = tx {
                                Ok(Self::Transaction(tx))
                            } else {
                                Err(ParsingError::Transaction)
                            };
                        } else {
                            Err(ParsingError::Transaction)
                        }
                    }
                    "join_pool" => {
                        if let Some(value) = map.get("npub") {
                            let npub: nostr::PublicKey = serde_json::from_value(value.clone())?;
                            Ok(Self::Join(Some(npub)))
                        } else {
                            Ok(Self::Join(None))
                        }
                    }
                    "credentials" => {
                        if let Some(value) = map.get("credentials") {
                            let cred: Credentials = serde_json::from_value(value.clone())?;
                            Ok(Self::Credentials(cred))
                        } else {
                            Err(ParsingError::Credential)
                        }
                    }
                    t => {
                        return Err(ParsingError::UnknownType(t.into()));
                    }
                };
            }

            if (map.contains_key("private_key") || map.contains_key("privateKey"))
                && map.contains_key("id")
            {
                let cred: Credentials = serde_json::from_value(Value::Object(map))?;
                return Ok(Self::Credentials(cred));
            }
        }
        Err(ParsingError::Unknown)
    }
}

#[derive(Debug)]
pub enum SerializeError {
    Transaction,
    Inputs,
    Outputs,
    SerdeJson(serde_json::Error),
    Psbt,
}

impl From<serde_json::Error> for SerializeError {
    fn from(value: serde_json::Error) -> Self {
        Self::SerdeJson(value)
    }
}

impl InputDataSigned {
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("txin".into(), Value::String(serialize_hex(&self.txin)));
        // `serialize_hex()` does not serialize the witness so a separate field is used
        let witness = &self.txin.witness;
        map.insert("witness".into(), Value::String(serialize_hex(witness)));
        if let Some(amount) = self.amount {
            map.insert("amount".into(), amount.to_sat().into());
        }
        map.into()
    }

    pub fn to_string(&self) -> Result<String, SerializeError> {
        let json = self.to_json();
        Ok(serde_json::to_string(&json)?)
    }

    pub fn to_string_pretty(&self) -> Result<String, SerializeError> {
        let json = self.to_json();
        Ok(serde_json::to_string_pretty(&json)?)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Result<Self, ParsingError> {
        let value: Value = serde_json::from_str(value)?;
        Self::from_value(value)
    }

    pub fn from_value(value: Value) -> Result<Self, ParsingError> {
        if let Value::Object(map) = value {
            let txin = map
                .get("txin")
                .ok_or(ParsingError::MissingKey("txin".into()))?;
            let mut txin: TxIn = if let Value::String(str) = txin {
                deserialize_hex(str).map_err(|_| ParsingError::Consensus)?
            } else {
                return Err(ParsingError::WrongValue("txin".into()));
            };

            // `serialize_hex()` does not serialize the witness so a separate field is used
            let witness = map
                .get("witness")
                .ok_or(ParsingError::MissingKey("witness".into()))?;
            let witness = if let Value::String(str) = witness {
                deserialize_hex(str).map_err(|_| ParsingError::Consensus)?
            } else {
                return Err(ParsingError::WrongValue("witness".into()));
            };
            txin.witness = witness;

            let amount: Option<Amount> = match map.get("amount") {
                Some(Value::Null) | None => None,
                Some(v) => Some(serde_json::from_value(v.clone())?),
            };
            Ok(Self { txin, amount })
        } else {
            Err(ParsingError::NotAnObject)
        }
    }
}

use base64ct::Encoding;

struct PythonJsonFormatter;

impl serde_json::ser::Formatter for PythonJsonFormatter {
    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        writer.write_all(b": ")
    }

    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }
}

fn to_python_json_string(value: &Value) -> Result<String, serde_json::Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, PythonJsonFormatter);
    serde::Serialize::serialize(value, &mut ser)?;
    Ok(String::from_utf8(buf).expect("valid utf8"))
}

impl PoolMessage {
    pub fn to_json(&self) -> Result<Value, SerializeError> {
        let mut map = Map::new();
        map.insert("version".into(), "1".into());
        match self {
            PoolMessage::Psbt(psbt) => {
                map.insert("type".into(), "input".into());
                let psbt_bytes = psbt.serialize();
                let psbt_b64 = base64ct::Base64::encode_string(&psbt_bytes);
                let mut input_obj = Map::new();
                input_obj.insert("psbt".into(), Value::String(psbt_b64));
                map.insert("input".into(), Value::Object(input_obj));
            }
            PoolMessage::Transaction(tx) => {
                map.insert("type".into(), "transaction".into());
                let raw = serialize_hex(tx);
                map.insert("transaction".into(), Value::String(raw));
            }
            PoolMessage::Join(npub) => {
                map.insert("type".into(), "join_pool".into());
                if let Some(npub) = npub {
                    map.insert("npub".into(), serde_json::to_value(npub)?);
                }
            }
            PoolMessage::Input(input) => {
                map.insert("type".into(), "input".into());
                map.insert("input".into(), input.to_json());
            }
            PoolMessage::Output(addr) => {
                map.insert("type".into(), "outputs".into());
                map.insert(
                    "outputs".into(),
                    Value::Array(vec![serde_json::to_value(addr)?]),
                );
            }
            PoolMessage::Credentials(cred) => {
                map.insert("type".into(), "credentials".into());
                map.insert("credentials".into(), serde_json::to_value(cred)?);
            }
        }
        Ok(map.into())
    }

    pub fn to_string(&self) -> Result<String, SerializeError> {
        let json = self.to_json()?;
        Ok(to_python_json_string(&json)?)
    }

    pub fn to_string_pretty(&self) -> Result<String, SerializeError> {
        let json = self.to_json()?;
        let str = serde_json::to_string_pretty(&json)?;
        Ok(str)
    }
}

pub fn default_transport() -> Transport {
    crate::nostr::Transport {
        vpn: Some(Vpn {
            enable: false,
            gateway: None,
        }),
        tor: Some(Tor { enable: false }),
    }
}

pub fn pool_id(key: &PublicKey) -> String {
    let mut engine = sha256::Hash::engine();
    engine.input(&key.clone().to_bytes());
    engine.input(
        &SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix timestamp must not fail")
            .as_micros()
            .to_be_bytes(),
    );
    sha256::Hash::from_engine(engine).to_string()
}

#[cfg(test)]
pub mod tests {
    use nostr::{Keys, PublicKey};

    use super::*;

    const RAW_POOL: &str = r#"
            {
              "type": "new_pool",
              "id": "123",
              "public_key": "0000000000000000000000000000000000000000000000000000000000000001",
              "denomination": 0.1,
              "peers": 5,
              "timeout": 12345,
              "relay": "",
              "fee_rate": 12,
              "transport": "vpn",
              "vpn_gateway": ""
            }
        "#;

    const RAW_POOL_RUST_LEGACY: &str = r#"
            {
              "version": "1",
              "type": "new_pool",
              "id": "123",
              "public_key": "0000000000000000000000000000000000000000000000000000000000000001",
              "network": "regtest",
              "denomination": 10000000,
              "peers": 5,
              "timeout": 12345,
              "relays": [],
              "fee_rate": 12,
              "transport": {
                "vpn": {
                  "enable": false
                }
              }
            }
        "#;

    #[test]
    fn pool_python_format() {
        let parsed: Pool = serde_json::from_str(RAW_POOL).unwrap();
        assert_eq!(parsed.version, Some("1".into()));
        assert_eq!(parsed.id, "123");
        assert_eq!(parsed.pool_type, PoolType::Create);
        assert_eq!(parsed.network, Network::Bitcoin);
        let payload = parsed.payload.as_ref().unwrap();
        assert_eq!(payload.denomination, Amount::from_btc(0.1).unwrap());
        assert_eq!(payload.peers, 5);
        assert_eq!(payload.relay, "");
        assert_eq!(payload.fee, Fee::Fixed(12));
        assert!(payload.transport.vpn.as_ref().unwrap().enable);
        assert!(!payload.transport.tor.as_ref().unwrap().enable);
    }

    #[test]
    fn pool_rust_legacy_format() {
        let parsed: Pool = serde_json::from_str(RAW_POOL_RUST_LEGACY).unwrap();
        assert_eq!(parsed.id, "123");
        assert_eq!(parsed.pool_type, PoolType::Create);
        assert_eq!(
            parsed.payload.as_ref().unwrap().denomination,
            Amount::from_btc(0.1).unwrap()
        );
    }

    #[test]
    fn pool_serialization_python_compat() {
        let pool = Pool {
            version: None,
            id: "test123".into(),
            pool_type: PoolType::Create,
            public_key: PublicKey::parse(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            network: Network::Regtest,
            payload: Some(PoolPayload {
                denomination: Amount::from_btc(0.001).unwrap(),
                peers: 2,
                timeout: Timeline::Simple(9999),
                relay: "wss://relay.example.com".into(),
                fee: Fee::Fixed(10),
                transport: Transport {
                    vpn: None,
                    tor: Some(Tor { enable: true }),
                },
                vpn_gateway: None,
            }),
        };

        let json = serde_json::to_string(&pool).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();

        assert_eq!(obj.get("type").unwrap(), "new_pool");
        assert_eq!(obj.get("denomination").unwrap(), &serde_json::json!(0.001));
        assert_eq!(obj.get("relay").unwrap(), "wss://relay.example.com");
        assert_eq!(obj.get("transport").unwrap(), "tor");
        // network should NOT be serialized
        assert!(obj.get("network").is_none());
    }

    #[test]
    fn input_data_signed() {
        let raw = r#"
            {
              "txin": "4f8176ffbca02baba974a4458eae799a87afa8a00317565827f035a8d45556ba0000000000fdffffff",
              "witness": "0247304402202be1d200c2c917c6bda981dd56b55a272f06af9aca9af4f9c8a23d4d0429bc420220623b571410104edc7773ab5cf71f3e10f814028aedef133591c1dab74eefc51f812103b1ea5528a8279cf184e76464ba5ed0a80cc6ca7c47899478fb7e4c9411404877",
              "amount": 1000000
            }
        "#;
        let ids = InputDataSigned::from_str(raw).unwrap();
        let serialized = ids.to_string().unwrap();
        let roundtrip = InputDataSigned::from_str(&serialized).unwrap();
        assert_eq!(ids, roundtrip);
    }

    #[test]
    fn input_legacy_format() {
        let raw = r#"
            {
              "version": "1",
              "type": "input",
              "input":
                {
                  "txin": "4f8176ffbca02baba974a4458eae799a87afa8a00317565827f035a8d45556ba0000000000fdffffff",
                  "witness": "0247304402202be1d200c2c917c6bda981dd56b55a272f06af9aca9af4f9c8a23d4d0429bc420220623b571410104edc7773ab5cf71f3e10f814028aedef133591c1dab74eefc51f812103b1ea5528a8279cf184e76464ba5ed0a80cc6ca7c47899478fb7e4c9411404877",
                  "amount": 1000000
                }
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Input(_)));
    }

    #[test]
    fn output() {
        let raw = r#"
            {
                "type": "output",
                "address": "bc1q4smd35jchznp0u442zhyv5yawf200ffet5kqc9"
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Output(_)));
        let serialized = msg.to_string().unwrap();
        assert!(serialized.contains(r#""type": "outputs""#), "{serialized}");
        assert!(serialized.contains(r#""outputs": ["#), "{serialized}");
        let roundtrip = PoolMessage::from_str(&serialized).unwrap();
        assert_eq!(msg, roundtrip);
    }

    #[test]
    fn output_with_version() {
        let raw = r#"
            {
                "version": "1",
                "type": "output",
                "address": "bc1q4smd35jchznp0u442zhyv5yawf200ffet5kqc9"
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Output(_)));
    }

    #[test]
    fn join() {
        let raw = r#"
            {
                "type": "join_pool"
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Join(None)));
        let serialized = msg.to_string().unwrap();
        assert!(serialized.contains(r#""version": "1""#), "{serialized}");
        let roundtrip = PoolMessage::from_str(&serialized).unwrap();
        assert_eq!(msg, roundtrip);
    }

    #[test]
    fn join_npub() {
        let raw = r#"
            {
                "type": "join_pool",
                "npub": "0000000000000000000000000000000000000000000000000000000000000001"
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Join(Some(_))));
        let serialized = msg.to_string().unwrap();
        assert!(serialized.contains(r#""version": "1""#), "{serialized}");
        assert!(serialized.contains(r#""npub""#), "{serialized}");
        let roundtrip = PoolMessage::from_str(&serialized).unwrap();
        assert_eq!(msg, roundtrip);
    }

    #[test]
    fn transaction() {
        let raw = r#"
            {
                "type": "transaction",
                "transaction": "020000000001050121a999ecdcd0f288d300e28719fcf859dae2b3b644292b5f2d2aecbb2e3de20100000000fdffffff16ccb309f4f9975b983b4bba70b4ab71d1721644f8204f816e549e94016a45d90100000000fdffffff9147ae6adeee48ad24f927e54779be2d1036c87fe04777e847e258a8a709d1d40000000000fdffffff423ce31bbdab2b76296ad846742539957951af6ab1587cf9e07eeb8aba0c51dc0100000000fdffffff5188353f0c80629d4efbf8753299ed09587c2d070d10b51d43127eac1dc8ef0c0100000000fdffffff0580969800000000001600140300036b09933e01bedbeae63850f29abc49164a8096980000000000160014185cede11f852fd6ca22d6b3f2383602f4639adb80969800000000001600142354a0caffe52b6521052e439327d8a41311e89780969800000000001600149ab1671aeb5cf5a2646044dac08a6aac1c3b5ca28096980000000000160014e60577e0f4a1a16837073810aad2d61d6810393d02473044022054a76a3f40098f18f202bebc4c373117b724e0de0ee44606a1570a9f123a648c022036b33c776a7bee07d936219333f2110a4bf1e966be52bca2cf79c8b4d384198e8121033cf9267abc8d886ee38c1ba032603099c0fbc8dfadcfcb43ab66bd0467e4adb90247304402202d7573747931547cb4c8ef26883435d3692357c7c92248e2e1b4327517aa476d02207be4bcde6284773fef9ce3794665a579c23a8805cc31c68405c42c0aea9c3af881210273d5ceafd9f15aa4b39ed7f0ab7f2dc365e4ccfaf9d88dd741d1e238a060fb0a024730440220634fb1d0dd7ab4726921caf790c41d3329a9685e6317afa5110c5b2bc9e22caf02200a8e76ace3e1bbda10da8c982b99658fa65e099bdd6c9c0209145f252c5a3c4d81210292f420e0790da79e55d55f9ecbe03a2545bc09d5bff0bf3268eb7779fb580b5d024730440220452f0c4ae26f0910290f62bf2ada8052e07d5ee7ebfed054a85391691d68c0640220461453b516902a07fc3c8fd206883a0e4f329f20da327af53d8a8edc4e6fae95812102445efffa41d0cf45382ceb6b5b02a16ee1e61957a91813ced84a2091ead6495102473044022017bc5084bab4c6ce796edd9f04e65463f4d0a2cb08b97be356e673d2982dddee02205b965d73cd4ad1c8647d76d5e201d718c315b3dc3c5987c6bc447bf1cac2b0ab812102fed36ddfe86cc993964b114780d66ff9c73867b7eae75d18e67a8d0490d68f6900000000"
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Transaction(_)));
        let serialized = msg.to_string().unwrap();
        let roundtrip = PoolMessage::from_str(&serialized).unwrap();
        assert_eq!(msg, roundtrip);
    }

    #[test]
    fn credential_legacy_format() {
        let raw = r#"
            {
                "version": "1",
                "type": "credentials",
                "credentials": {
                  "id": "1234",
                  "key": "0000000000000000000000000000000000000000000000000000000000000001"
                }
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Credentials(_)));
    }

    #[test]
    fn credential_python_format() {
        let raw = r#"
            {
                "id": "test_pool_123",
                "public_key": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "denomination": 0.001,
                "peers": 2,
                "timeout": 1700000000,
                "relay": "wss://relay.example.com",
                "private_key": "0000000000000000000000000000000000000000000000000000000000000001",
                "fee_rate": 10,
                "transport": "tor",
                "vpn_gateway": ""
            }
        "#;
        let msg = PoolMessage::from_str(raw).unwrap();
        if let PoolMessage::Credentials(cred) = msg {
            assert_eq!(cred.id, "test_pool_123");
            assert_eq!(cred.relay, Some("wss://relay.example.com".into()));
            assert_eq!(cred.peers, Some(2));
            assert_eq!(cred.fee_rate, Some(10));
            assert_eq!(cred.transport, Some("tor".into()));
        } else {
            panic!("expected Credentials");
        }
    }

    #[test]
    fn credential_roundtrip() {
        let cred = Credentials {
            id: "test123".into(),
            private_key: nostr::SecretKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            public_key: Some("abcd".into()),
            denomination: Some(Amount::from_btc(0.001).unwrap()),
            peers: Some(3),
            timeout: Some(9999),
            relay: Some("wss://relay.test".into()),
            fee_rate: Some(5),
            transport: Some("tor".into()),
            vpn_gateway: Some("".into()),
        };

        let msg = PoolMessage::Credentials(cred);
        let serialized = msg.to_string().unwrap();
        let roundtrip = PoolMessage::from_str(&serialized).unwrap();
        if let (PoolMessage::Credentials(a), PoolMessage::Credentials(b)) = (&msg, &roundtrip) {
            assert_eq!(a, b);
        } else {
            panic!("expected Credentials");
        }
    }

    #[test]
    fn pool_event() {
        let raw = RAW_POOL;
        let pool: Pool = serde_json::from_str(raw).unwrap();
        let keys = Keys::generate();
        let builder: EventBuilder = pool.clone().try_into().unwrap();
        let event = builder.to_event(&keys).unwrap();
        let roundtrip: Pool = event.try_into().unwrap();
        assert_eq!(pool, roundtrip);
    }

    #[test]
    fn python_json_compat() {
        let join = PoolMessage::Join(None);
        let s = join.to_string().unwrap();
        assert!(s.contains(r#""version": "1""#), "join version: {s}");
        assert!(s.contains(r#""type": "join_pool""#), "join: {s}");

        let output = PoolMessage::Output(
            Address::from_str("bc1q4smd35jchznp0u442zhyv5yawf200ffet5kqc9").unwrap(),
        );
        let s = output.to_string().unwrap();
        assert!(s.contains(r#""type": "outputs""#), "output: {s}");
        assert!(s.contains(r#""outputs": ["#), "output array: {s}");
    }

    #[test]
    fn input_data_signed_roundtrip_missing_amount() {
        use miniscript::bitcoin::TxIn;

        let input = InputDataSigned {
            txin: TxIn {
                previous_output:
                    "0000000000000000000000000000000000000000000000000000000000000001:0"
                        .parse()
                        .unwrap(),
                sequence: miniscript::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: miniscript::bitcoin::Witness::new(),
                ..Default::default()
            },
            amount: None,
        };

        let json = input.to_json();
        assert!(json.get("amount").is_none());

        let roundtripped = InputDataSigned::from_value(json).unwrap();
        assert_eq!(roundtripped.amount, None);
        assert_eq!(
            roundtripped.txin.previous_output,
            input.txin.previous_output
        );
    }

    #[test]
    fn psbt_serializes_as_input_and_deserializes_to_input() {
        let psbt_b64 = "cHNidP8BAHEBAAAAATCOqpCuU8eoeQsSsEYb/n6FBozrlytjjDIR+W1Hn6M4AQAAAAD/////AhS96wsAAAAAFgAUQJxQ/6Eg9bri4/Exvn+r1A+IeyAUvesLAAAAABYAFOKsiuNywQeZ9EKlQS3yiGHMzfoIAAAAAAABAJoBAAAAAqBOLjCwhAdjtE7N/F2075driKWW27JFdFzWDe/DiqN3AAAAAAD/////2WadwSyHIg42zrc1vG7raPqMxs/jIu2cfnCPC3LZDDsAAAAAAP////8C3L3rCwAAAAAWABT5hnV0YVQn7PKvwXKQ4UtCTTt6H9y96wsAAAAAFgAUWaR6myJN4T1ti9u/yXNJlcn56vIAAAAAAQEf3L3rCwAAAAAWABRZpHqbIk3hPW2L27/Jc0mVyfnq8iICAzRmCdPhKH7oBWrhiYZkP60MQajbsP8dhTnFHpkr75HORzBEAiAg165L5FwWmE/MLz6fQ+eGNF1GDc3aGx/4TtUBPZkH/AIgRG2zZM8I7rdpJemQUHpuHht3AbNiAAWN1gouECRylbiBAQMEgQAAAAAAAA==";
        let psbt_bytes = base64ct::Base64::decode_vec(psbt_b64).unwrap();
        let psbt = Psbt::deserialize(&psbt_bytes).unwrap();

        let expected_input: InputDataSigned = psbt.clone().try_into().unwrap();
        let msg = PoolMessage::Psbt(psbt);

        let json = msg.to_json().unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.get("version").unwrap(), "1");
        assert_eq!(obj.get("type").unwrap(), "input");
        assert!(obj
            .get("input")
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("psbt"));

        let serialized = msg.to_string().unwrap();
        let roundtrip = PoolMessage::from_str(&serialized).unwrap();
        if let PoolMessage::Input(input) = roundtrip {
            assert_eq!(
                input.txin.previous_output,
                expected_input.txin.previous_output
            );
            assert_eq!(input.amount, expected_input.amount);
            assert!(!input.txin.witness.is_empty());
        } else {
            panic!(
                "expected PoolMessage::Input after roundtrip, got {:?}",
                roundtrip
            );
        }
    }

    #[test]
    fn pool_camel_case_format() {
        let raw = r#"{"type":"new_pool","id":"fdlrvsgmqd1730582572","publicKey":"312929d99a20b93e2f44281d1110e2a051051b1968e856a3362171a076e4a471","denomination":1.9999894,"peers":2,"timeout":1730583172,"relay":"wss://nostr.fmt.wiz.biz","feeRate":1,"transport":"VPN","vpnGateway":"vpn04-ams.riseup.net"}"#;
        let pool: Pool = serde_json::from_str(raw).unwrap();
        assert_eq!(pool.pool_type, PoolType::Create);
        assert_eq!(pool.id, "fdlrvsgmqd1730582572");
        let payload = pool.payload.as_ref().unwrap();
        assert_eq!(payload.fee, Fee::Fixed(1));
        assert_eq!(payload.vpn_gateway, Some("vpn04-ams.riseup.net".into()));
        assert!(payload.transport.vpn.as_ref().unwrap().enable);
    }

    #[test]
    fn pool_versioned_format() {
        let raw = r#"{
            "version": "1",
            "id": "e37076afaf4a0054fd144f0b843c174173e7d0620a572572c0a34e6b78023afe",
            "network": "regtest",
            "type": "create",
            "public_key": "8f09f051d2a699bfd9fc289b7edb49cda50768067181df23735f3e921955001b",
            "denomination": 1000000,
            "peers": 2,
            "timeout": 1731808735,
            "relays": ["ws://127.0.0.1:34889"],
            "fee_rate": 10,
            "transport": {
                "vpn": { "enable": false },
                "tor": { "enable": false }
            }
        }"#;
        let pool: Pool = serde_json::from_str(raw).unwrap();
        assert_eq!(pool.pool_type, PoolType::Create);
        assert_eq!(pool.version, Some("1".into()));
        let payload = pool.payload.as_ref().unwrap();
        assert_eq!(payload.denomination, Amount::from_sat(1000000));
        assert_eq!(payload.peers, 2);
        assert_eq!(payload.relay, "ws://127.0.0.1:34889");
        assert_eq!(payload.fee, Fee::Fixed(10));
    }

    #[test]
    fn credential_camel_case_format() {
        let raw = r#"{"id":"fdlrvsgmqd1730582572","publicKey":"312929d99a20b93e2f44281d1110e2a051051b1968e856a3362171a076e4a471","denomination":1.9999894,"peers":2,"timeout":1730583172,"relay":"wss://nostr.fmt.wiz.biz","privateKey":"2d9b289395139525983ddaf95862529bd3cb5fe5107c5d8db3159de8993f62a2","feeRate":1,"transport":"VPN","vpnGateway":"vpn04-ams.riseup.net"}"#;
        let msg = PoolMessage::from_str(raw).unwrap();
        if let PoolMessage::Credentials(cred) = msg {
            assert_eq!(cred.id, "fdlrvsgmqd1730582572");
            assert_eq!(
                cred.public_key,
                Some("312929d99a20b93e2f44281d1110e2a051051b1968e856a3362171a076e4a471".into())
            );
            assert_eq!(cred.fee_rate, Some(1));
            assert_eq!(cred.vpn_gateway, Some("vpn04-ams.riseup.net".into()));
        } else {
            panic!("expected Credentials, got {:?}", msg);
        }
    }

    #[test]
    fn credential_versioned_format() {
        let raw = r#"{
            "version": "1",
            "type": "credentials",
            "credentials": {
                "id": "e37076afaf4a0054fd144f0b843c174173e7d0620a572572c0a34e6b78023afe",
                "key": "a0013422636dc37072dac80f0cdd6e3e15f54dc3a449dd62c383e9ed9487e402"
            }
        }"#;
        let msg = PoolMessage::from_str(raw).unwrap();
        if let PoolMessage::Credentials(cred) = msg {
            assert_eq!(
                cred.id,
                "e37076afaf4a0054fd144f0b843c174173e7d0620a572572c0a34e6b78023afe"
            );
        } else {
            panic!("expected Credentials, got {:?}", msg);
        }
    }

    #[test]
    fn output_versioned_format() {
        let raw = r#"{
            "version": "1",
            "type": "outputs",
            "outputs": ["bcrt1qe4c2u4hujydlk2dftde82rh72yhkvsxrec7j8p"]
        }"#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Output(_)));
    }

    #[test]
    fn input_versioned_format() {
        let raw = r#"{
            "version": "1",
            "type": "inputs",
            "inputs": [{
                "txin": "91cfa09cbfa0d5f2a78bccf9348aa7f6e760afaf2ff16f45dcedb7038ddfdb240100000000fdffffff",
                "witness": "0247304402206c6494b8fc9932384f64377f741b2fc7389e4238a0520d045263434351a5955c0220164d8904368a0745bc1106d9b17a1abf45390850bb473e5b1b0d4487ce102a6a812103e20092911874cd94b8969c08458a7eadf291b4e51f850f86c5b1b22edcf17353",
                "amount": 1100000
            }]
        }"#;
        let msg = PoolMessage::from_str(raw).unwrap();
        if let PoolMessage::Input(input) = msg {
            assert_eq!(input.amount, Some(Amount::from_sat(1100000)));
        } else {
            panic!("expected Input, got {:?}", msg);
        }
    }

    #[test]
    fn input_hex_field() {
        let raw = r#"{"hex":"cHNidP8BAHEBAAAAATCOqpCuU8eoeQsSsEYb/n6FBozrlytjjDIR+W1Hn6M4AQAAAAD/////AhS96wsAAAAAFgAUQJxQ/6Eg9bri4/Exvn+r1A+IeyAUvesLAAAAABYAFOKsiuNywQeZ9EKlQS3yiGHMzfoIAAAAAAABAJoBAAAAAqBOLjCwhAdjtE7N/F2075driKWW27JFdFzWDe/DiqN3AAAAAAD/////2WadwSyHIg42zrc1vG7raPqMxs/jIu2cfnCPC3LZDDsAAAAAAP////8C3L3rCwAAAAAWABT5hnV0YVQn7PKvwXKQ4UtCTTt6H9y96wsAAAAAFgAUWaR6myJN4T1ti9u/yXNJlcn56vIAAAAAAQEf3L3rCwAAAAAWABRZpHqbIk3hPW2L27/Jc0mVyfnq8iICAzRmCdPhKH7oBWrhiYZkP60MQajbsP8dhTnFHpkr75HORzBEAiAg165L5FwWmE/MLz6fQ+eGNF1GDc3aGx/4TtUBPZkH/AIgRG2zZM8I7rdpJemQUHpuHht3AbNiAAWN1gouECRylbiBAQMEgQAAAAAAAA==","type":"input"}"#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Input(_)));
    }

    #[test]
    fn output_with_hex_null() {
        let raw = r#"{"address":"tb1qu2kg4cmjcyrenazz54qjmu5gv8xvm7sgn0frw8","hex":null,"type":"output"}"#;
        let msg = PoolMessage::from_str(raw).unwrap();
        assert!(matches!(msg, PoolMessage::Output(_)));
    }
}
