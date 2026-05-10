use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, bail};
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use ark::{ProtocolEncoding, VtxoId, VtxoPolicy};
use bark::swap::btc_ark::{ArkOffer, BtcClaimAdaptorPackage, SwapId, SwapStatus};

use crate::validation::{
    bytes_hex, bytes32_from_hex, hash_json_hex, script_from_hex, signature_from_hex,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RelayFile {
    pub(crate) protocol: String,
    pub(crate) version: u16,
    pub(crate) swap_id: String,
    pub(crate) status: SwapStatus,
    pub(crate) request: BtcArkRequestArtifact,
    pub(crate) terms: Option<OfferTerms>,
    pub(crate) ark_transfer: Option<ArkTransferArtifact>,
    pub(crate) btc_funding: Option<BtcFundingArtifact>,
    pub(crate) claim_request: Option<BtcClaimRequestArtifact>,
    pub(crate) ark_claim_partial: Option<ArkClaimPartialArtifact>,
    pub(crate) btc_claim_adaptor: Option<BtcClaimAdaptorArtifact>,
    #[serde(default)]
    pub(crate) btc_refund: Option<BtcRefundArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OfferTerms {
    pub(crate) amount_sat: u64,
    pub(crate) btc_payout_address: String,
    pub(crate) btc_payout_script_hex: String,
    pub(crate) adaptor_point: String,
    pub(crate) ark_payer_claim_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BtcArkRequestArtifact {
    pub(crate) amount_sat: u64,
    pub(crate) ark_receive: String,
    pub(crate) btc_payer_claim_pubkey: String,
    pub(crate) btc_refund_pubkey: String,
    pub(crate) fee_rate_sat_vb: u64,
    pub(crate) refund_delay_blocks: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArkTransferArtifact {
    pub(crate) offer: ArkOfferArtifact,
    pub(crate) transfer_package_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArkOfferArtifact {
    pub(crate) id: String,
    pub(crate) amount_sat: u64,
    pub(crate) btc_payout_script_hex: String,
    pub(crate) ark_input_ids: Vec<String>,
    pub(crate) ark_receive_policy_hex: String,
    pub(crate) ark_server_pubkey: String,
    pub(crate) adaptor_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BtcFundingArtifact {
    pub(crate) funding_txid: String,
    pub(crate) funding_vout: u32,
    pub(crate) funding_tx_hex: String,
    pub(crate) lock_address: String,
    pub(crate) lock_amount_sat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BtcRefundArtifact {
    pub(crate) refund_txid: String,
    pub(crate) refund_tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BtcClaimRequestArtifact {
    pub(crate) claim_tx_hex: String,
    pub(crate) claim_sighash_hex: String,
    pub(crate) tap_tweak_hex: String,
    pub(crate) btc_payer_public_nonce_hex: String,
    pub(crate) claim_amount_sat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArkClaimPartialArtifact {
    pub(crate) ark_public_nonce_hex: String,
    pub(crate) ark_partial_sig_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BtcClaimAdaptorArtifact {
    pub(crate) adaptor_point: String,
    pub(crate) aggregate_key: String,
    pub(crate) sighash_hex: String,
    pub(crate) pre_signature_hex: String,
}

impl RelayFile {
    pub(crate) fn new_request(swap_id: SwapId, request: BtcArkRequestArtifact) -> Self {
        Self {
            protocol: "btc-ark".to_owned(),
            version: 2,
            swap_id: swap_id.to_string(),
            status: SwapStatus::Requested,
            request,
            terms: None,
            ark_transfer: None,
            btc_funding: None,
            claim_request: None,
            ark_claim_partial: None,
            btc_claim_adaptor: None,
            btc_refund: None,
        }
    }

    pub(crate) fn swap_id(&self) -> anyhow::Result<SwapId> {
        SwapId::from_str(&self.swap_id).context("relay swap id is invalid")
    }

    pub(crate) fn require_swap(&self, expected: SwapId) -> anyhow::Result<()> {
        if self.swap_id()? != expected {
            bail!(
                "relay file contains swap {}, but command requested {}",
                self.swap_id,
                expected
            );
        }
        Ok(())
    }

    pub(crate) fn terms(&self) -> anyhow::Result<&OfferTerms> {
        self.terms
            .as_ref()
            .context("Ark transfer terms are missing; run ark-offer first")
    }
}

impl ArkTransferArtifact {
    pub(crate) fn commitment_hash_hex(&self) -> anyhow::Result<String> {
        hash_json_hex(self)
    }
}

impl ArkOfferArtifact {
    pub(crate) fn from_offer(offer: &ArkOffer) -> Self {
        Self {
            id: offer.id.to_string(),
            amount_sat: offer.amount.to_sat(),
            btc_payout_script_hex: bytes_hex(offer.btc_payout_script.as_bytes()),
            ark_input_ids: offer
                .ark_input_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            ark_receive_policy_hex: offer.ark_receive_policy.serialize_hex(),
            ark_server_pubkey: offer.ark_server_pubkey.to_string(),
            adaptor_point: offer.adaptor_point.to_string(),
        }
    }

    pub(crate) fn to_offer(&self) -> anyhow::Result<ArkOffer> {
        Ok(ArkOffer {
            id: SwapId::from_str(&self.id).context("invalid Ark offer swap id")?,
            amount: bitcoin::Amount::from_sat(self.amount_sat),
            btc_payout_script: script_from_hex(&self.btc_payout_script_hex)?,
            ark_input_ids: self
                .ark_input_ids
                .iter()
                .map(|id| VtxoId::from_str(id).context("invalid Ark input VTXO id"))
                .collect::<anyhow::Result<Vec<_>>>()?,
            ark_receive_policy: VtxoPolicy::deserialize_hex(&self.ark_receive_policy_hex)
                .context("invalid Ark receive policy")?,
            ark_server_pubkey: PublicKey::from_str(&self.ark_server_pubkey)
                .context("invalid Ark server pubkey")?,
            adaptor_point: PublicKey::from_str(&self.adaptor_point)
                .context("invalid adaptor point")?,
        })
    }
}

impl BtcClaimAdaptorArtifact {
    pub(crate) fn from_package(package: &BtcClaimAdaptorPackage) -> Self {
        Self {
            adaptor_point: package.adaptor_point.to_string(),
            aggregate_key: package.aggregate_key.to_string(),
            sighash_hex: bytes_hex(&package.sighash),
            pre_signature_hex: bytes_hex(&package.pre_signature.as_pre_signature().serialize()),
        }
    }

    pub(crate) fn to_package(&self) -> anyhow::Result<BtcClaimAdaptorPackage> {
        let pre_signature = signature_from_hex(&self.pre_signature_hex)?;
        Ok(BtcClaimAdaptorPackage {
            adaptor_point: PublicKey::from_str(&self.adaptor_point)
                .context("invalid BTC claim adaptor point")?,
            aggregate_key: XOnlyPublicKey::from_str(&self.aggregate_key)
                .context("invalid BTC claim aggregate key")?,
            sighash: bytes32_from_hex(&self.sighash_hex)?,
            pre_signature: ark::musig::AdaptorPreSignature::new(pre_signature),
        })
    }
}

pub(crate) fn coordinator_path(coordinator: &str) -> PathBuf {
    coordinator
        .strip_prefix("file://")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(coordinator))
}

pub(crate) async fn store_relay(coordinator: &str, relay: &RelayFile) -> anyhow::Result<()> {
    let path = coordinator_path(coordinator);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create relay dir {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(relay)?;
    ensure_relay_secret_free(&bytes)?;
    atomic_write(&path, bytes)
        .await
        .with_context(|| format!("failed to write relay file {}", path.display()))
}

pub(crate) async fn load_relay(coordinator: &str) -> anyhow::Result<RelayFile> {
    let path = coordinator_path(coordinator);
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read relay file {}", path.display()))?;
    let relay: RelayFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse relay file {}", path.display()))?;
    if relay.protocol != "btc-ark" || relay.version != 2 {
        bail!("unsupported BTC-Ark relay file");
    }
    Ok(relay)
}

fn ensure_relay_secret_free(bytes: &[u8]) -> anyhow::Result<()> {
    let text = std::str::from_utf8(bytes).context("relay JSON is not UTF-8")?;
    for forbidden in [
        "mnemonic",
        "adaptor_secret",
        "adaptor_secret_hex",
        "secret_nonce",
        "btc_secret_nonce",
    ] {
        if text.contains(forbidden) {
            bail!("relay file contains secret-bearing field {forbidden}");
        }
    }
    Ok(())
}

async fn atomic_write(path: &Path, bytes: Vec<u8>) -> anyhow::Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("json")
    ));
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_secret_free_check_rejects_secret_bearing_fields() {
        let err = ensure_relay_secret_free(br#"{"btc_secret_nonce":"deadbeef"}"#).unwrap_err();
        assert!(
            err.to_string()
                .contains("relay file contains secret-bearing field"),
            "{err:#}",
        );
    }
}
