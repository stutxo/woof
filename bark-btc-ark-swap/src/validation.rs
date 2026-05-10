use anyhow::{Context, bail};
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{SecretKey, schnorr};
use bitcoin::{FeeRate, ScriptBuf};
use serde::Serialize;

pub(crate) fn fee_rate_from_sat_vb(fee_rate: u64) -> anyhow::Result<FeeRate> {
    if fee_rate == 0 {
        bail!("fee-rate must be greater than zero");
    }
    Ok(FeeRate::from_sat_per_vb_u32(
        u32::try_from(fee_rate).context("fee-rate is too large")?,
    ))
}

pub(crate) fn hash_json_hex<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value).context("failed to serialize value for hash")?;
    Ok(bytes_hex(
        &bitcoin::hashes::sha256::Hash::hash(&bytes).to_byte_array(),
    ))
}

pub(crate) fn bytes_hex(bytes: &[u8]) -> String {
    bytes.as_hex().to_string()
}

pub(crate) fn bytes_from_hex(hex: &str) -> anyhow::Result<Vec<u8>> {
    Vec::<u8>::from_hex(hex).context("invalid hex")
}

pub(crate) fn bytes32_from_hex(hex: &str) -> anyhow::Result<[u8; 32]> {
    bytes_from_hex(hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte hex string"))
}

pub(crate) fn script_from_hex(hex: &str) -> anyhow::Result<ScriptBuf> {
    Ok(ScriptBuf::from_bytes(bytes_from_hex(hex)?))
}

pub(crate) fn secret_key_hex(secret_key: SecretKey) -> String {
    bytes_hex(&secret_key.secret_bytes())
}

pub(crate) fn secret_key_from_hex(hex: &str) -> anyhow::Result<SecretKey> {
    SecretKey::from_slice(&bytes32_from_hex(hex)?).context("invalid secret key")
}

pub(crate) fn signature_from_hex(hex: &str) -> anyhow::Result<schnorr::Signature> {
    schnorr::Signature::from_slice(&bytes_from_hex(hex)?).context("invalid schnorr signature")
}

pub(crate) fn public_nonce_from_hex(hex: &str) -> anyhow::Result<ark::musig::PublicNonce> {
    let bytes = bytes_from_hex(hex)?;
    let bytes = <[u8; 66]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("expected 66-byte MuSig public nonce"))?;
    ark::musig::PublicNonce::from_byte_array(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
}

pub(crate) fn partial_sig_from_hex(hex: &str) -> anyhow::Result<ark::musig::PartialSignature> {
    let bytes = bytes_from_hex(hex)?;
    let bytes = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("expected 32-byte MuSig partial signature"))?;
    ark::musig::PartialSignature::from_byte_array(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
}
