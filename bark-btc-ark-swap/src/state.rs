use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use ark::VtxoId;
use bark::swap::btc_ark::{SwapId, SwapRole, SwapStatus};

use crate::relay::ArkTransferArtifact;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredBtcArkSwap {
    pub(crate) swap_id: String,
    pub(crate) role: SwapRole,
    pub(crate) status: SwapStatus,
    pub(crate) coordinator: String,
    pub(crate) amount_sat: Option<u64>,
    pub(crate) btc_payout: Option<String>,
    #[serde(default)]
    pub(crate) offer_adaptor_point: Option<String>,
    #[serde(default)]
    pub(crate) ark_payer_claim_pubkey: Option<String>,
    pub(crate) ark_receive: Option<String>,
    pub(crate) fee_rate_sat_vb: Option<u64>,
    pub(crate) ark_claim_key_index: Option<u32>,
    pub(crate) btc_claim_key_index: Option<u32>,
    pub(crate) refund_key_index: Option<u32>,
    pub(crate) adaptor_secret_hex: Option<String>,
    pub(crate) btc_secret_nonce: Option<ark::musig::DangerousSecretNonce>,
    pub(crate) btc_claim_sighash_hex: Option<String>,
    #[serde(default)]
    pub(crate) btc_claim_public_nonce_hex: Option<String>,
    #[serde(default)]
    pub(crate) accepted_ark_transfer_hash_hex: Option<String>,
    #[serde(default)]
    pub(crate) accepted_ark_input_ids: Option<Vec<String>>,
}

impl StoredBtcArkSwap {
    pub(crate) fn set_accepted_ark_transfer(
        &mut self,
        artifact: &ArkTransferArtifact,
    ) -> anyhow::Result<()> {
        self.accepted_ark_transfer_hash_hex = Some(artifact.commitment_hash_hex()?);
        self.accepted_ark_input_ids = Some(artifact.offer.ark_input_ids.clone());
        Ok(())
    }

    pub(crate) fn verify_accepted_ark_transfer(
        &self,
        artifact: &ArkTransferArtifact,
    ) -> anyhow::Result<()> {
        let expected = self
            .accepted_ark_transfer_hash_hex
            .as_ref()
            .context("accepted Ark transfer hash is missing from local state")?;
        let actual = artifact.commitment_hash_hex()?;
        if *expected != actual {
            bail!("relay Ark transfer changed after local acceptance");
        }
        Ok(())
    }

    pub(crate) fn accepted_ark_input_ids(&self) -> anyhow::Result<Vec<VtxoId>> {
        self.accepted_ark_input_ids
            .as_ref()
            .context("accepted Ark input IDs are missing from local state")?
            .iter()
            .map(|id| VtxoId::from_str(id).context("invalid accepted Ark input VTXO id"))
            .collect()
    }

    pub(crate) fn require_ark_payer_transfer_material(&self) -> anyhow::Result<()> {
        self.require_ark_payer_offer_material()?;
        self.accepted_ark_transfer_hash_hex
            .as_ref()
            .context("accepted Ark transfer hash is missing from local state")?;
        Ok(())
    }

    pub(crate) fn require_ark_payer_offer_material(&self) -> anyhow::Result<()> {
        self.adaptor_secret_hex
            .as_ref()
            .context("Ark payer adaptor secret is missing from local state")?;
        self.ark_claim_key_index
            .context("Ark payer claim key index is missing from local state")?;
        Ok(())
    }

    pub(crate) fn require_btc_payer_claim_nonce_material(&self) -> anyhow::Result<()> {
        self.btc_secret_nonce
            .as_ref()
            .context("BTC secret nonce is missing from local state")?;
        self.btc_claim_sighash_hex
            .as_ref()
            .context("BTC claim sighash is missing from local state")?;
        self.btc_claim_public_nonce_hex
            .as_ref()
            .context("BTC claim public nonce is missing from local state")?;
        Ok(())
    }
}

pub(crate) fn swap_state_path(datadir: &Path, swap_id: &str, role: SwapRole) -> PathBuf {
    datadir
        .join("swap")
        .join(format!("btc-ark-{}-{}.json", swap_id, role_slug(role)))
}

pub(crate) async fn store_swap_state(
    datadir: &Path,
    state: &StoredBtcArkSwap,
) -> anyhow::Result<()> {
    let dir = datadir.join("swap");
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create swap state dir {}", dir.display()))?;
    let path = swap_state_path(datadir, &state.swap_id, state.role);
    let bytes = serde_json::to_vec_pretty(state)?;
    atomic_write(&path, bytes)
        .await
        .with_context(|| format!("failed to write swap state {}", path.display()))?;
    Ok(())
}

pub(crate) async fn load_swap_state(
    datadir: &Path,
    swap_id: SwapId,
    role: SwapRole,
) -> anyhow::Result<StoredBtcArkSwap> {
    let path = swap_state_path(datadir, &swap_id.to_string(), role);
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read swap state {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn role_slug(role: SwapRole) -> &'static str {
    match role {
        SwapRole::BtcPayer => "btc-payer",
        SwapRole::ArkPayer => "ark-payer",
    }
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
    use ark::VtxoId;

    use super::*;
    use crate::relay::{ArkOfferArtifact, ArkTransferArtifact};

    fn transfer_artifact(input_id: String) -> ArkTransferArtifact {
        ArkTransferArtifact {
            offer: ArkOfferArtifact {
                id: "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
                amount_sat: 80_000,
                btc_payout_script_hex: "51".to_owned(),
                ark_input_ids: vec![input_id],
                ark_receive_policy_hex: "00".to_owned(),
                ark_server_pubkey:
                    "020000000000000000000000000000000000000000000000000000000000000001".to_owned(),
                adaptor_point: "020000000000000000000000000000000000000000000000000000000000000002"
                    .to_owned(),
            },
            transfer_package_hex: "deadbeef".to_owned(),
        }
    }

    fn base_state() -> StoredBtcArkSwap {
        StoredBtcArkSwap {
            swap_id: "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            role: SwapRole::BtcPayer,
            status: SwapStatus::BtcFunded,
            coordinator: "relay.json".to_owned(),
            amount_sat: Some(80_000),
            btc_payout: None,
            offer_adaptor_point: None,
            ark_payer_claim_pubkey: None,
            ark_receive: None,
            fee_rate_sat_vb: Some(1),
            ark_claim_key_index: None,
            btc_claim_key_index: Some(0),
            refund_key_index: Some(0),
            adaptor_secret_hex: None,
            btc_secret_nonce: None,
            btc_claim_sighash_hex: None,
            btc_claim_public_nonce_hex: None,
            accepted_ark_transfer_hash_hex: None,
            accepted_ark_input_ids: None,
        }
    }

    #[test]
    fn accepted_transfer_pin_rejects_later_relay_tamper() {
        let input_id = VtxoId::from_slice(&[7u8; 36]).unwrap().to_string();
        let artifact = transfer_artifact(input_id.clone());
        let mut state = base_state();

        state.set_accepted_ark_transfer(&artifact).unwrap();
        assert_eq!(
            state.accepted_ark_input_ids.as_ref().unwrap(),
            &vec![input_id]
        );

        let mut tampered = artifact;
        tampered.transfer_package_hex = "feedface".to_owned();
        let err = state.verify_accepted_ark_transfer(&tampered).unwrap_err();
        assert!(
            err.to_string()
                .contains("relay Ark transfer changed after local acceptance"),
            "{err:#}",
        );
    }

    #[test]
    fn btc_payer_claim_nonce_material_requires_local_secret_material() {
        let state = base_state();

        let err = state.require_btc_payer_claim_nonce_material().unwrap_err();
        assert!(
            err.to_string().contains("BTC secret nonce is missing"),
            "{err:#}",
        );
    }
}
