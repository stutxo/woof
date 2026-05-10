//! Bark-native BTC-to-Ark VTXO PTLC swap primitives.
//!
//! This module keeps wallet-side protocol primitives and signing helpers. Relay
//! and communication orchestration live outside the wallet crate.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, XOnlyPublicKey, schnorr};
use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness, absolute::LockTime, sighash, taproot, transaction::Version,
};
use bitcoin_ext::{BlockDelta, BlockHeight, TaprootSpendInfoExt, TxOutExt};

use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{
    ArkoorPackageBuilder, ArkoorPackageCosignResponse, TransferPackageVerificationError,
    TransferableAdaptorArkoorPackage,
};
use ark::musig::{self, AdaptorPreSignature, AdaptorSecret};
use ark::vtxo::Full;
use ark::{Vtxo, VtxoId, VtxoPolicy};
use server_rpc::protos;

use crate::Wallet;
use crate::onchain::{PreparePsbt, SignPsbt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SwapId([u8; 32]);

impl SwapId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        Self(rand::random())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SwapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl FromStr for SwapId {
    type Err = SwapIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(SwapIdParseError);
        }

        let mut bytes = [0u8; 32];
        for (idx, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = decode_hex_nibble(chunk[0]).ok_or(SwapIdParseError)?;
            let lo = decode_hex_nibble(chunk[1]).ok_or(SwapIdParseError)?;
            bytes[idx] = (hi << 4) | lo;
        }

        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwapIdParseError;

impl fmt::Display for SwapIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid swap id")
    }
}

impl std::error::Error for SwapIdParseError {}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwapRole {
    BtcPayer,
    ArkPayer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwapStatus {
    Requested,
    Offered,
    BtcFunded,
    BtcClaimReady,
    ArkCompleted,
    Refunded,
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct ArkOffer {
    pub id: SwapId,
    pub amount: Amount,
    pub btc_payout_script: ScriptBuf,
    pub ark_input_ids: Vec<VtxoId>,
    pub ark_receive_policy: VtxoPolicy,
    pub ark_server_pubkey: PublicKey,
    pub adaptor_point: PublicKey,
}

pub struct PreparedArkSwapPackage {
    pub offer: ArkOffer,
    pub transfer: TransferableAdaptorArkoorPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArkTransferOfferError {
    #[error("Ark transfer swap id mismatch: expected {expected}, got {got}")]
    SwapIdMismatch { expected: SwapId, got: SwapId },
    #[error("Ark transfer amount mismatch: expected {expected}, got {got}")]
    AmountMismatch { expected: Amount, got: Amount },
    #[error("Ark transfer BTC payout script mismatch")]
    BtcPayoutScriptMismatch,
    #[error("Ark transfer receive policy mismatch")]
    ArkReceivePolicyMismatch,
    #[error("Ark transfer server pubkey mismatch: expected {expected}, got {got}")]
    ServerPubkeyMismatch { expected: PublicKey, got: PublicKey },
    #[error("Ark transfer adaptor point mismatch: expected {expected}, got {got}")]
    AdaptorPointMismatch { expected: PublicKey, got: PublicKey },
}

#[derive(Clone, Debug)]
pub struct BtcLockContract {
    pub amount: Amount,
    pub refund_delay: BlockDelta,
    pub refund_script: ScriptBuf,
    pub taproot: taproot::TaprootSpendInfo,
    pub address: Address,
}

impl BtcLockContract {
    pub fn new(
        amount: Amount,
        network: Network,
        btc_payer_pubkey: PublicKey,
        ark_payer_pubkey: PublicKey,
        refund_pubkey: XOnlyPublicKey,
        refund_delay: BlockDelta,
    ) -> Self {
        let aggregate_key = musig::combine_keys([btc_payer_pubkey, ark_payer_pubkey])
            .x_only_public_key()
            .0;
        let refund_script = ark::scripts::delayed_sign(refund_delay, refund_pubkey);
        let taproot = taproot::TaprootBuilder::new()
            .add_leaf(0, refund_script.clone())
            .expect("valid refund leaf")
            .finalize(&ark::SECP, aggregate_key)
            .expect("valid taproot tree");
        let address = Address::from_script(&taproot.script_pubkey(), network)
            .expect("taproot script has an address");

        Self {
            amount,
            refund_delay,
            refund_script,
            taproot,
            address,
        }
    }

    pub fn funding_destination(&self) -> (Address, Amount) {
        (self.address.clone(), self.amount)
    }

    pub fn txout(&self) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: self.address.script_pubkey(),
        }
    }

    pub fn refund_sequence(&self) -> Sequence {
        Sequence::from_height(self.refund_delay)
    }

    pub fn refund_is_mature(&self, funding_confirmations: u32) -> bool {
        funding_confirmations > u32::from(self.refund_delay)
    }

    pub fn prepare_funding_psbt<W: PreparePsbt>(
        &self,
        wallet: &mut W,
        fee_rate: FeeRate,
    ) -> Result<Psbt> {
        Ok(wallet.prepare_tx(&[self.funding_destination()], fee_rate)?)
    }

    pub async fn fund_with_onchain<W>(
        &self,
        wallet: &mut W,
        fee_rate: FeeRate,
    ) -> Result<Transaction>
    where
        W: PreparePsbt + SignPsbt,
    {
        let psbt = self.prepare_funding_psbt(wallet, fee_rate)?;
        wallet
            .finish_tx(psbt)
            .await
            .context("failed to sign BTC lock funding transaction")
    }
}

#[derive(Clone, Debug)]
pub struct BtcClaimAdaptorPackage {
    pub adaptor_point: PublicKey,
    pub aggregate_key: XOnlyPublicKey,
    pub sighash: [u8; 32],
    pub pre_signature: AdaptorPreSignature,
}

impl BtcClaimAdaptorPackage {
    pub fn verify(&self) -> Result<()> {
        self.pre_signature
            .verify_adaptor(self.adaptor_point, self.aggregate_key, self.sighash)
            .context("BTC claim adaptor pre-signature does not verify against T")
    }

    pub fn finalize_with_secret(&self, secret: AdaptorSecret) -> Result<schnorr::Signature> {
        self.verify()?;
        Ok(self
            .pre_signature
            .finalize_with_secret(secret, self.aggregate_key, self.sighash)?)
    }

    pub fn recover_secret(&self, final_sig: schnorr::Signature) -> Result<AdaptorSecret> {
        ark::SECP
            .verify_schnorr(
                &final_sig,
                &Message::from_digest(self.sighash),
                &self.aggregate_key,
            )
            .context("final BTC claim signature does not verify")?;
        Ok(self
            .pre_signature
            .recover_secret(final_sig, self.adaptor_point)?)
    }
}

pub fn build_cooperative_claim_tx(
    funding_outpoint: OutPoint,
    btc_lock: &BtcLockContract,
    btc_payout_script: ScriptBuf,
    fee_rate: FeeRate,
) -> Result<Transaction> {
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: btc_lock.amount,
            script_pubkey: btc_payout_script,
        }],
    };

    let mut fee_probe = tx.clone();
    fee_probe.input[0].witness.push([0u8; 64]);
    let fee = fee_rate * fee_probe.weight();
    tx.output[0].value = btc_lock.amount.checked_sub(fee).with_context(|| {
        format!(
            "BTC claim fee {fee} exceeds locked amount {}",
            btc_lock.amount
        )
    })?;
    if !tx.output[0].is_standard() {
        bail!(
            "BTC claim output {} to {} is non-standard after subtracting fee {fee}",
            tx.output[0].value,
            tx.output[0].script_pubkey,
        );
    }
    Ok(tx)
}

pub fn cooperative_claim_sighash(
    claim_tx: &Transaction,
    btc_lock: &BtcLockContract,
) -> Result<[u8; 32]> {
    Ok(sighash::SighashCache::new(claim_tx)
        .taproot_key_spend_signature_hash(
            0,
            &sighash::Prevouts::All(&[btc_lock.txout()]),
            sighash::TapSighashType::Default,
        )
        .context("failed to compute BTC claim key-spend sighash")?
        .to_byte_array())
}

pub fn build_refund_tx(
    funding_outpoint: OutPoint,
    btc_lock: &BtcLockContract,
    refund_script_pubkey: ScriptBuf,
    fee_rate: FeeRate,
) -> Result<Transaction> {
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: btc_lock.refund_sequence(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: btc_lock.amount,
            script_pubkey: refund_script_pubkey,
        }],
    };

    let control_block = btc_lock
        .taproot
        .control_block(&(
            btc_lock.refund_script.clone(),
            taproot::LeafVersion::TapScript,
        ))
        .context("BTC refund script is not in taproot tree")?;
    let control_block_bytes = control_block.serialize();

    let mut fee_probe = tx.clone();
    let dummy_signature = [0u8; 64];
    let witness_items: [&[u8]; 3] = [
        dummy_signature.as_slice(),
        btc_lock.refund_script.as_bytes(),
        control_block_bytes.as_slice(),
    ];
    fee_probe.input[0].witness = Witness::from_slice(&witness_items);
    let fee = fee_rate * fee_probe.weight();
    tx.output[0].value = btc_lock.amount.checked_sub(fee).with_context(|| {
        format!(
            "BTC refund fee {fee} exceeds locked amount {}",
            btc_lock.amount
        )
    })?;
    if !tx.output[0].is_standard() {
        bail!(
            "BTC refund output {} to {} is non-standard after subtracting fee {fee}",
            tx.output[0].value,
            tx.output[0].script_pubkey,
        );
    }

    Ok(tx)
}

pub fn sign_refund_tx(
    mut refund_tx: Transaction,
    btc_lock: &BtcLockContract,
    refund_keypair: &Keypair,
) -> Result<Transaction> {
    let control_block = btc_lock
        .taproot
        .control_block(&(
            btc_lock.refund_script.clone(),
            taproot::LeafVersion::TapScript,
        ))
        .context("BTC refund script is not in taproot tree")?;
    let leaf_hash =
        taproot::TapLeafHash::from_script(&btc_lock.refund_script, taproot::LeafVersion::TapScript);
    let sighash = sighash::SighashCache::new(&refund_tx)
        .taproot_script_spend_signature_hash(
            0,
            &sighash::Prevouts::All(&[btc_lock.txout()]),
            leaf_hash,
            sighash::TapSighashType::Default,
        )
        .context("failed to compute BTC refund script-spend sighash")?;
    let signature = ark::SECP.sign_schnorr_with_aux_rand(
        &Message::from_digest(sighash.to_byte_array()),
        refund_keypair,
        &rand::random(),
    );
    let control_block_bytes = control_block.serialize();
    refund_tx.input[0].witness = Witness::from_slice(&[
        &signature[..],
        btc_lock.refund_script.as_bytes(),
        &control_block_bytes,
    ]);

    Ok(refund_tx)
}

pub fn sign_cooperative_claim_partial(
    ark_payer_keypair: &Keypair,
    btc_payer_pubkey: PublicKey,
    btc_payer_public_nonce: &musig::PublicNonce,
    sighash: [u8; 32],
    tap_tweak: Option<[u8; 32]>,
) -> (musig::PublicNonce, musig::PartialSignature) {
    musig::deterministic_partial_sign(
        ark_payer_keypair,
        [btc_payer_pubkey],
        &[btc_payer_public_nonce],
        sighash,
        tap_tweak,
    )
}

pub fn build_cooperative_claim_adaptor_package_from_parts(
    btc_payer_keypair: &Keypair,
    btc_secret_nonce: musig::SecretNonce,
    btc_public_nonce: &musig::PublicNonce,
    ark_payer_pubkey: PublicKey,
    ark_public_nonce: &musig::PublicNonce,
    ark_partial_sig: &musig::PartialSignature,
    sighash: [u8; 32],
    tap_tweak: Option<[u8; 32]>,
    adaptor_point: PublicKey,
) -> Result<BtcClaimAdaptorPackage> {
    let aggregate_nonce = musig::nonce_agg(&[btc_public_nonce, ark_public_nonce]);
    let (_partial_sig, pre_sig) = musig::partial_sign(
        [btc_payer_keypair.public_key(), ark_payer_pubkey],
        aggregate_nonce,
        btc_payer_keypair,
        btc_secret_nonce,
        sighash,
        tap_tweak,
        Some(&[ark_partial_sig]),
    );

    let aggregate_key = if let Some(tweak) = tap_tweak {
        musig::tweaked_key_agg([btc_payer_keypair.public_key(), ark_payer_pubkey], tweak).1
    } else {
        musig::combine_keys([btc_payer_keypair.public_key(), ark_payer_pubkey])
    }
    .x_only_public_key()
    .0;

    let package = BtcClaimAdaptorPackage {
        adaptor_point,
        aggregate_key,
        sighash,
        pre_signature: AdaptorPreSignature::new(
            pre_sig.expect("pre-signature exists when counterparty partial is provided"),
        ),
    };
    package.verify()?;
    Ok(package)
}

pub fn build_cooperative_claim_adaptor_package(
    btc_payer_keypair: &Keypair,
    ark_payer_keypair: &Keypair,
    sighash: [u8; 32],
    tap_tweak: Option<[u8; 32]>,
    adaptor_point: PublicKey,
) -> Result<BtcClaimAdaptorPackage> {
    let (btc_secret_nonce, btc_public_nonce) =
        musig::adaptor_nonce_pair_with_msg(btc_payer_keypair, &sighash, adaptor_point)?;

    let (ark_public_nonce, ark_partial_sig) = sign_cooperative_claim_partial(
        ark_payer_keypair,
        btc_payer_keypair.public_key(),
        &btc_public_nonce,
        sighash,
        tap_tweak,
    );

    build_cooperative_claim_adaptor_package_from_parts(
        btc_payer_keypair,
        btc_secret_nonce,
        &btc_public_nonce,
        ark_payer_keypair.public_key(),
        &ark_public_nonce,
        &ark_partial_sig,
        sighash,
        tap_tweak,
        adaptor_point,
    )
}

pub fn verify_ark_transfer_offer(
    offer: &ArkOffer,
    expected_id: SwapId,
    expected_amount: Amount,
    expected_btc_payout_script: &ScriptBuf,
    expected_receive_policy: &VtxoPolicy,
    expected_server_pubkey: PublicKey,
    expected_adaptor_point: PublicKey,
) -> std::result::Result<(), ArkTransferOfferError> {
    if offer.id != expected_id {
        return Err(ArkTransferOfferError::SwapIdMismatch {
            expected: expected_id,
            got: offer.id,
        });
    }
    if offer.amount != expected_amount {
        return Err(ArkTransferOfferError::AmountMismatch {
            expected: expected_amount,
            got: offer.amount,
        });
    }
    if offer.btc_payout_script != *expected_btc_payout_script {
        return Err(ArkTransferOfferError::BtcPayoutScriptMismatch);
    }
    if offer.ark_receive_policy != *expected_receive_policy {
        return Err(ArkTransferOfferError::ArkReceivePolicyMismatch);
    }
    if offer.ark_server_pubkey != expected_server_pubkey {
        return Err(ArkTransferOfferError::ServerPubkeyMismatch {
            expected: expected_server_pubkey,
            got: offer.ark_server_pubkey,
        });
    }
    if offer.adaptor_point != expected_adaptor_point {
        return Err(ArkTransferOfferError::AdaptorPointMismatch {
            expected: expected_adaptor_point,
            got: offer.adaptor_point,
        });
    }

    Ok(())
}

pub fn verify_ark_transfer_before_acceptance(
    offer: &ArkOffer,
    transfer: &TransferableAdaptorArkoorPackage,
    minimum_output_expiry_height: BlockHeight,
) -> Result<(), TransferPackageVerificationError> {
    transfer.verify_public_transfer(
        &offer.ark_input_ids,
        &offer.ark_receive_policy,
        offer.amount,
        offer.ark_server_pubkey,
        offer.adaptor_point,
    )?;

    for output in transfer.build_unsigned_vtxos() {
        let expiry_height = output.expiry_height();
        if expiry_height <= minimum_output_expiry_height {
            return Err(TransferPackageVerificationError::OutputExpiryTooSoon {
                vtxo_id: output.id(),
                expiry_height,
                minimum_expiry_height: minimum_output_expiry_height,
            });
        }
    }

    Ok(())
}

impl Wallet {
    pub async fn prepare_btc_ark_transfer(
        &self,
        destination: &ark::Address,
        amount: Amount,
        btc_payout_script: ScriptBuf,
        adaptor_point: PublicKey,
    ) -> Result<PreparedArkSwapPackage> {
        self.validate_arkoor_address(destination)
            .await
            .context("address validation failed")?;

        let (mut srv, ark_info) = self.require_server().await?;
        let dest = ArkoorDestination {
            total_amount: amount,
            policy: destination.policy().clone(),
        };
        let inputs = self.select_vtxos_to_cover(dest.total_amount).await?;
        let (input_ids, inputs) = inputs
            .into_iter()
            .map(|v| (v.id(), v))
            .collect::<(Vec<_>, Vec<_>)>();

        self.register_vtxo_transactions_with_server(&inputs)
            .await
            .context("failed to register BTC-Ark input VTXO transactions with server")?;

        let (change_keypair, change_key_index) = self.peek_next_keypair().await?;
        let change_pubkey = change_keypair.public_key();
        let change_policy = VtxoPolicy::new_pubkey(change_pubkey);

        if dest.policy.user_pubkey() == change_pubkey {
            bail!("Cannot create BTC-Ark transfer to same address as change");
        }

        let mut user_keypairs = Vec::with_capacity(inputs.len());
        for vtxo in &inputs {
            user_keypairs.push(self.get_vtxo_key(vtxo).await?);
        }

        let builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
            inputs.into_iter().map(|v| v.vtxo),
            dest.clone(),
            change_policy.clone(),
        )
        .context("failed to construct BTC-Ark arkoor package")?
        .generate_user_adaptor_nonces(&user_keypairs, adaptor_point)
        .context("invalid number of keypairs")?;

        let response = srv
            .client
            .request_arkoor_cosign(protos::ArkoorPackageCosignRequest::from(
                builder.cosign_request(),
            ))
            .await
            .context("server failed to cosign BTC-Ark arkoor package")?
            .into_inner();

        let cosign_responses = ArkoorPackageCosignResponse::try_from(response)
            .context("failed to parse BTC-Ark cosign response from server")?;

        let transfer = builder
            .user_adaptor_cosign(&user_keypairs, cosign_responses)
            .context("failed to adaptor-cosign BTC-Ark arkoor package")?
            .into_transfer_package();

        if transfer
            .build_unsigned_vtxos()
            .any(|vtxo| *vtxo.policy() == change_policy)
        {
            self.db
                .store_vtxo_key(change_key_index, change_pubkey)
                .await?;
        }

        let offer = ArkOffer {
            id: SwapId::random(),
            amount,
            btc_payout_script,
            ark_input_ids: input_ids,
            ark_receive_policy: dest.policy,
            ark_server_pubkey: ark_info.server_pubkey,
            adaptor_point,
        };

        Ok(PreparedArkSwapPackage { offer, transfer })
    }

    pub async fn complete_btc_ark_transfer(
        &self,
        transfer: TransferableAdaptorArkoorPackage,
        secret: AdaptorSecret,
    ) -> Result<Vec<Vtxo<Full>>> {
        let signed_vtxos = transfer
            .finalize_with_secret(secret)
            .context("failed to finalize BTC-Ark arkoor package")?
            .build_signed_vtxos();

        self.register_vtxo_transactions_with_server(&signed_vtxos)
            .await
            .context("failed to register BTC-Ark output VTXO transactions with server")?;

        for vtxo in &signed_vtxos {
            self.import_vtxo(vtxo)
                .await
                .context("failed to import BTC-Ark output VTXO")?;
        }

        Ok(signed_vtxos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::secp256k1::{SecretKey, rand};

    #[test]
    fn final_btc_claim_signature_reveals_t() {
        let btc_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let ark_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
        let claim = build_cooperative_claim_adaptor_package(
            &btc_payer_keypair,
            &ark_payer_keypair,
            [9u8; 32],
            Some([7u8; 32]),
            secret.point(),
        )
        .expect("claim adaptor package");

        let final_sig = claim
            .finalize_with_secret(secret)
            .expect("final claim signature");
        let recovered = claim.recover_secret(final_sig).expect("revealed secret");

        assert_eq!(recovered.secret_key(), secret.secret_key());
    }

    #[test]
    fn recover_secret_rejects_invalid_final_signature() {
        let btc_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let ark_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
        let claim = build_cooperative_claim_adaptor_package(
            &btc_payer_keypair,
            &ark_payer_keypair,
            [9u8; 32],
            Some([7u8; 32]),
            secret.point(),
        )
        .expect("claim adaptor package");

        let final_sig = claim
            .finalize_with_secret(secret)
            .expect("final claim signature");
        let mut invalid_sig_bytes = final_sig.serialize();
        invalid_sig_bytes[0] ^= 1;
        let invalid_sig = schnorr::Signature::from_slice(&invalid_sig_bytes)
            .expect("invalid signature remains schnorr-shaped");

        claim
            .pre_signature
            .recover_secret(invalid_sig, claim.adaptor_point)
            .expect("tampered signature still reveals same scalar delta");
        assert!(claim.recover_secret(invalid_sig).is_err());
    }

    #[test]
    fn verify_ark_transfer_offer_rejects_wrong_receive_policy() {
        let server_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
        let expected_policy =
            VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
        let wrong_policy =
            VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
        let offer = ArkOffer {
            id: SwapId::random(),
            amount: Amount::from_sat(10_000),
            btc_payout_script: ScriptBuf::new_p2tr(
                &ark::SECP,
                Keypair::new(&ark::SECP, &mut rand::thread_rng())
                    .x_only_public_key()
                    .0,
                None,
            ),
            ark_input_ids: vec![],
            ark_receive_policy: wrong_policy,
            ark_server_pubkey: server_keypair.public_key(),
            adaptor_point: secret.point(),
        };

        let err = verify_ark_transfer_offer(
            &offer,
            offer.id,
            offer.amount,
            &offer.btc_payout_script,
            &expected_policy,
            server_keypair.public_key(),
            secret.point(),
        )
        .expect_err("wrong receive policy must be rejected");
        assert_eq!(ArkTransferOfferError::ArkReceivePolicyMismatch, err);
    }

    #[test]
    fn cooperative_claim_rejects_dust_output_after_fee() {
        let btc_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let ark_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let payout_key = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let btc_lock = BtcLockContract::new(
            Amount::from_sat(400),
            Network::Regtest,
            btc_payer_keypair.public_key(),
            ark_payer_keypair.public_key(),
            btc_payer_keypair.x_only_public_key().0,
            6,
        );

        let err = build_cooperative_claim_tx(
            OutPoint::null(),
            &btc_lock,
            ScriptBuf::new_p2tr(&ark::SECP, payout_key.x_only_public_key().0, None),
            FeeRate::from_sat_per_vb(1).expect("valid fee rate"),
        )
        .expect_err("dust BTC claim output must be rejected");
        assert!(err.to_string().contains("BTC claim output"));
    }

    #[test]
    fn verify_ark_transfer_before_acceptance_rejects_expired_outputs() {
        let user_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let server_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let (_funding_tx, input) = ark::test_util::dummy::DummyTestVtxoSpec {
            amount: Amount::from_sat(10_000),
            fee: Amount::ZERO,
            expiry_height: 100,
            exit_delta: 12,
            user_keypair,
            server_keypair,
        }
        .build();
        let amount = input.amount();
        let input_id = input.id();
        let receive_policy =
            VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
        let change_policy =
            VtxoPolicy::new_pubkey(Keypair::new(&ark::SECP, &mut rand::thread_rng()).public_key());
        let secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));

        let user_builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
            [input],
            ArkoorDestination {
                total_amount: amount,
                policy: receive_policy.clone(),
            },
            change_policy,
        )
        .expect("valid arkoor package")
        .generate_user_adaptor_nonces(&[user_keypair], secret.point())
        .expect("valid user nonces");
        let cosign_response =
            ArkoorPackageBuilder::from_cosign_request(user_builder.cosign_request())
                .expect("valid cosign request")
                .server_cosign(&server_keypair)
                .expect("server cosigns")
                .cosign_response();
        let transfer = user_builder
            .user_adaptor_cosign(&[user_keypair], cosign_response)
            .expect("user adaptor cosigns")
            .into_transfer_package();
        let output_id = transfer.build_unsigned_vtxos().next().unwrap().id();
        let offer = ArkOffer {
            id: SwapId::random(),
            amount,
            btc_payout_script: ScriptBuf::new(),
            ark_input_ids: vec![input_id],
            ark_receive_policy: receive_policy,
            ark_server_pubkey: server_keypair.public_key(),
            adaptor_point: secret.point(),
        };

        let err = verify_ark_transfer_before_acceptance(&offer, &transfer, 100)
            .expect_err("expired outputs must be rejected");
        assert!(
            matches!(
                err,
                TransferPackageVerificationError::OutputExpiryTooSoon {
                    vtxo_id,
                    expiry_height: 100,
                    minimum_expiry_height: 100,
                } if vtxo_id == output_id
            ),
            "{err:#}",
        );
    }

    #[test]
    fn refund_is_valid_only_after_csv_delay() {
        let btc_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let ark_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let refund_key = btc_payer_keypair.x_only_public_key().0;
        let lock = BtcLockContract::new(
            Amount::from_sat(50_000),
            Network::Regtest,
            btc_payer_keypair.public_key(),
            ark_payer_keypair.public_key(),
            refund_key,
            6,
        );

        assert_eq!(lock.refund_sequence(), Sequence::from_height(6));
        assert!(!lock.refund_is_mature(6));
        assert!(lock.refund_is_mature(7));
    }

    #[test]
    fn refund_tx_uses_csv_refund_path() {
        let btc_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let ark_payer_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let refund_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let destination_keypair = Keypair::new(&ark::SECP, &mut rand::thread_rng());
        let lock = BtcLockContract::new(
            Amount::from_sat(50_000),
            Network::Regtest,
            btc_payer_keypair.public_key(),
            ark_payer_keypair.public_key(),
            refund_keypair.x_only_public_key().0,
            6,
        );
        let destination_script =
            ScriptBuf::new_p2tr(&ark::SECP, destination_keypair.x_only_public_key().0, None);

        let refund_tx = build_refund_tx(
            OutPoint::null(),
            &lock,
            destination_script.clone(),
            FeeRate::from_sat_per_vb(1).expect("valid fee rate"),
        )
        .expect("refund transaction");
        assert_eq!(refund_tx.input[0].sequence, Sequence::from_height(6));
        assert_eq!(refund_tx.output[0].script_pubkey, destination_script);
        assert!(refund_tx.output[0].value < lock.amount);

        let signed = sign_refund_tx(refund_tx.clone(), &lock, &refund_keypair)
            .expect("signed refund transaction");
        assert_eq!(signed.compute_txid(), refund_tx.compute_txid());
        assert_eq!(signed.input[0].witness.len(), 3);
    }
}
