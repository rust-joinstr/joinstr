use std::fmt::Display;

use crate::electrum;

#[derive(Debug)]
pub enum Error {
    NotEnoughPeers(usize, usize),
    TxToPsbt,
    InitPsbtExists,
    InitPsbtNotCreated,
    DoubleSpend,
    InputAmountTooLow,
    TxAlreadyFinalyzed,
    AddressReuse,
    InputValueNotMatch,
    InputDoesNotExists,
    FeeTooLow(u64, u64, u64),
    Electrum(electrum::Error),
    FailVerifyAmount,
    AmountMissing,
    InputValueOutOfRange(u64, u64, u64),
    FeeBoundsViolation(u64, u64, u64),
    Unknown(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotEnoughPeers(peers, requested) => write!(
                f,
                "Not enough peer to generate the PSBT: {}/{}",
                peers, requested
            ),
            Error::TxToPsbt => write!(f, "Fail to generate PSBT from unsigned Transaction"),
            Error::InitPsbtExists => write!(f, "The PSBT already exists"),
            Error::InitPsbtNotCreated => write!(f, "The PSBT have not been created yet"),
            Error::DoubleSpend => {
                write!(f, "This input have already been included in the coinjoin")
            }
            Error::InputAmountTooLow => {
                write!(f, "Sum of inputs amounts if inferior to output amount")
            }
            Error::TxAlreadyFinalyzed => write!(f, "This coinjoin tx have already been finalized"),
            Error::AddressReuse => write!(
                f,
                "The address provided for input had already received coins in the past"
            ),
            Error::InputValueNotMatch => write!(
                f,
                "The input amount supplied by the peer did not match on-chain amount"
            ),
            Error::InputDoesNotExists => write!(
                f,
                "The input outpoint supplied by peer did not exists in our chain"
            ),
            Error::FeeTooLow(expected_sat_vb, weight, sats) => write!(
                f,
                "Fee are inferior than the expected minimal \
                fee rate ({} sats/vb):\n \
                tx_weight: {} \n \
                fee_amount: {}",
                expected_sat_vb, weight, sats
            ),
            Error::Electrum(e) => write!(f, "Electrum error: {}", e),
            Error::FailVerifyAmount => write!(f, "Fail to verify the input amount"),
            Error::AmountMissing => write!(
                f,
                "The input amount is missing and no electrum client provided"
            ),
            Error::InputValueOutOfRange(value, min, max) => write!(
                f,
                "Input value {} sats is outside allowed range [{}, {}]",
                value, min, max
            ),
            Error::FeeBoundsViolation(fee, min, max) => write!(
                f,
                "Fee {} sats is outside allowed bounds [{}, {}]",
                fee, min, max
            ),
            Error::Unknown(e) => write!(f, "Unknown error: {}", e),
        }
    }
}

impl From<electrum::Error> for Error {
    fn from(value: electrum::Error) -> Self {
        Error::Electrum(value)
    }
}
