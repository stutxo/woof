use std::io;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, bail};
use bitcoin::consensus::encode::{deserialize_hex as consensus_deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey, rand, schnorr};
use bitcoin::{Amount, OutPoint, Transaction, Txid, address};
use serde::Serialize;

use ark::ProtocolEncoding;
use ark::musig::{self, AdaptorSecret, DangerousSecretNonce};
use bark::Wallet;
use bark::onchain::{ChainSync, OnchainWallet};
use bark::swap::btc_ark::{
    ArkOffer, ArkTransferAcceptanceOptions, BtcLockContract, SwapId, SwapRole, SwapStatus,
    build_cooperative_claim_adaptor_package_from_parts, build_cooperative_claim_tx,
    build_refund_tx, cooperative_claim_sighash, sign_cooperative_claim_partial, sign_refund_tx,
    verify_ark_transfer_before_acceptance_with_options, verify_ark_transfer_offer,
};

use crate::relay::{
    ArkClaimPartialArtifact, ArkOfferArtifact, ArkTransferArtifact, BtcArkRequestArtifact,
    BtcClaimAdaptorArtifact, BtcClaimRequestArtifact, BtcFundingArtifact, BtcRefundArtifact,
    OfferTerms, RelayFile, load_relay, store_relay,
};
use crate::state::{StoredBtcArkSwap, load_swap_state, store_swap_state};
use crate::validation::{
    bytes_hex, bytes32_from_hex, fee_rate_from_sat_vb, partial_sig_from_hex, public_nonce_from_hex,
    script_from_hex, secret_key_from_hex, secret_key_hex,
};

fn output_json<T>(value: &T)
where
    T: ?Sized + Serialize,
{
    serde_json::to_writer_pretty(io::stdout(), value).expect("JSON write failed");
    println!();
}

#[derive(clap::Subcommand)]
pub enum SwapCommand {
    /// BTC-to-Ark VTXO PTLC swap commands
    #[command(name = "btc-ark", subcommand)]
    BtcArk(BtcArkCommand),
}

// Swap safety boundary: the BTC payer funds only after seeing public Ark terms,
// and the Ark payer creates the irreversible Ark transfer only after the BTC
// lock is visible. The relay file is just the POC message bundle between peers.
#[derive(clap::Subcommand)]
pub enum BtcArkCommand {
    /// Start the file-relay coordinator placeholder
    #[command()]
    Coordinator {
        /// Listen address or relay file reserved for the coordinator transport
        #[arg(long)]
        listen: String,
    },

    /// Create a BTC-payer swap request
    #[command(name = "btc-request")]
    BtcRequest {
        /// JSON relay file. Copy this file between parties for the POC.
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        amount: Amount,
        #[arg(long = "ark-receive")]
        ark_receive: ark::Address,
        #[arg(long = "fee-rate")]
        fee_rate: u64,
        /// CSV refund delay for the BTC lock.
        #[arg(long = "refund-delay", default_value_t = 144)]
        refund_delay: u16,
    },

    /// Publish the Ark payer's swap terms before the BTC payer funds the lock
    #[command(name = "ark-offer")]
    ArkOffer {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
        #[arg(long = "btc-payout")]
        btc_payout: bitcoin::Address<address::NetworkUnchecked>,
    },

    /// Prepare the adaptor-locked Ark transfer after the BTC lock is funded
    #[command(name = "ark-transfer")]
    ArkTransfer {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
        /// Permit creating the Ark transfer before the BTC lock confirms. Useful only for local POCs.
        #[arg(long)]
        allow_unconfirmed: bool,
    },

    /// Abort from the Ark payer side before revealing the adaptor secret
    #[command(name = "ark-abort")]
    ArkAbort {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
    },

    /// Fund the BTC lock against the offered terms
    #[command(name = "btc-fund")]
    BtcFund {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
    },

    /// Sign the Ark payer's partial signature for the BTC claim
    #[command(name = "ark-sign-btc-claim")]
    ArkSignBtcClaim {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
        /// Permit signing the BTC claim before the BTC lock confirms. Useful only for local POCs.
        #[arg(long)]
        allow_unconfirmed: bool,
    },

    /// Build the BTC payer's adaptor signature package for the BTC claim
    #[command(name = "btc-build-claim-adaptor")]
    BtcBuildClaimAdaptor {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
        /// Permit accepting Ark transfer outputs that expire before the BTC refund window. Testing only.
        #[arg(long)]
        allow_short_ark_transfer_expiry: bool,
    },

    /// Finalize and broadcast the Ark payer's BTC claim
    #[command(name = "ark-finalize-btc-claim")]
    ArkFinalizeBtcClaim {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
        /// Permit claiming BTC before the BTC lock confirms. Useful only for local POCs.
        #[arg(long)]
        allow_unconfirmed: bool,
    },

    /// Complete the BTC payer's Ark VTXO transfer using the revealed adaptor secret
    #[command(name = "btc-complete-ark")]
    BtcCompleteArk {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
    },

    /// BTC payer CSV fallback if the Ark payer stops after BTC funding
    #[command(name = "btc-refund")]
    BtcRefund {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        swap: String,
        /// Optional refund destination. Defaults to a fresh on-chain wallet address.
        #[arg(long)]
        destination: Option<bitcoin::Address<address::NetworkUnchecked>>,
    },
}

pub async fn execute_swap_command(
    swap_command: SwapCommand,
    wallet: &mut Wallet,
    onchain: &mut OnchainWallet,
    datadir: &Path,
) -> anyhow::Result<()> {
    match swap_command {
        SwapCommand::BtcArk(cmd) => execute_btc_ark_command(cmd, wallet, onchain, datadir).await,
    }
}

pub async fn execute_btc_ark_coordinator_command(listen: String) -> anyhow::Result<()> {
    output_json(&serde_json::json!({
        "protocol": "btc-ark",
        "coordinator": "file-relay",
        "listen": listen,
        "status": "ready",
        "transport": "json-file"
    }));
    Ok(())
}

async fn execute_btc_ark_command(
    command: BtcArkCommand,
    wallet: &mut Wallet,
    onchain: &mut OnchainWallet,
    datadir: &Path,
) -> anyhow::Result<()> {
    match command {
        BtcArkCommand::Coordinator { listen } => {
            execute_btc_ark_coordinator_command(listen).await?;
        }
        BtcArkCommand::BtcRequest {
            coordinator,
            amount,
            ark_receive,
            fee_rate,
            refund_delay,
        } => {
            wallet
                .validate_arkoor_address(&ark_receive)
                .await
                .context("invalid Ark receive address")?;
            let _fee_rate = fee_rate_from_sat_vb(fee_rate)?;
            let (btc_claim_keypair, btc_claim_key_index) =
                wallet.derive_store_next_keypair().await?;
            let swap_id = SwapId::random();
            let relay = RelayFile::new_request(
                swap_id,
                BtcArkRequestArtifact {
                    amount_sat: amount.to_sat(),
                    ark_receive: ark_receive.to_string(),
                    btc_payer_claim_pubkey: btc_claim_keypair.public_key().to_string(),
                    btc_refund_pubkey: btc_claim_keypair.x_only_public_key().0.to_string(),
                    fee_rate_sat_vb: fee_rate,
                    refund_delay_blocks: refund_delay,
                },
            );

            let state = StoredBtcArkSwap {
                swap_id: swap_id.to_string(),
                role: SwapRole::BtcPayer,
                status: SwapStatus::Requested,
                coordinator: coordinator.clone(),
                amount_sat: Some(amount.to_sat()),
                btc_payout: None,
                offer_adaptor_point: None,
                ark_payer_claim_pubkey: None,
                ark_receive: Some(ark_receive.to_string()),
                fee_rate_sat_vb: Some(fee_rate),
                ark_claim_key_index: None,
                btc_claim_key_index: Some(btc_claim_key_index),
                refund_key_index: Some(btc_claim_key_index),
                adaptor_secret_hex: None,
                btc_secret_nonce: None,
                btc_claim_sighash_hex: None,
                btc_claim_public_nonce_hex: None,
                accepted_ark_transfer_hash_hex: None,
                accepted_ark_input_ids: None,
            };
            store_swap_state(datadir, &state).await?;
            store_relay(&coordinator, &relay).await?;
            output_step(&relay, "ark-offer", &coordinator);
        }
        BtcArkCommand::ArkOffer {
            coordinator,
            swap,
            btc_payout,
        } => {
            let network = wallet.network().await?;
            let btc_payout = btc_payout.require_network(network).with_context(|| {
                format!(
                    "BTC payout address is not valid for configured network {}",
                    network
                )
            })?;
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;
            ensure_relay_not_cancelled(&relay)?;
            if relay.terms.is_some() {
                let state = load_swap_state(datadir, swap_id, SwapRole::ArkPayer).await?;
                ensure_swap_state_not_cancelled(&state)?;
                state.require_ark_payer_offer_material()?;
                verify_relay_matches_local_state(wallet, &state, &relay).await?;
                output_step(&relay, next_btc_ark_step(&relay), &coordinator);
                return Ok(());
            }
            if relay.ark_transfer.is_some() {
                bail!("swap has an Ark transfer but no offer terms");
            }
            let destination = ark::Address::from_str(&relay.request.ark_receive)
                .context("invalid requested Ark receive address")?;
            wallet
                .validate_arkoor_address(&destination)
                .await
                .context("invalid requested Ark receive address")?;
            let _fee_rate = fee_rate_from_sat_vb(relay.request.fee_rate_sat_vb)?;
            let adaptor_secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
            let (ark_claim_keypair, ark_claim_key_index) =
                wallet.derive_store_next_keypair().await?;

            relay.terms = Some(OfferTerms {
                amount_sat: relay.request.amount_sat,
                btc_payout_address: btc_payout.to_string(),
                btc_payout_script_hex: bytes_hex(btc_payout.script_pubkey().as_bytes()),
                adaptor_point: adaptor_secret.point().to_string(),
                ark_payer_claim_pubkey: ark_claim_keypair.public_key().to_string(),
            });
            relay.status = SwapStatus::Offered;

            let state = StoredBtcArkSwap {
                swap_id: swap_id.to_string(),
                role: SwapRole::ArkPayer,
                status: SwapStatus::Offered,
                coordinator: coordinator.clone(),
                amount_sat: Some(relay.request.amount_sat),
                btc_payout: Some(btc_payout.to_string()),
                offer_adaptor_point: Some(adaptor_secret.point().to_string()),
                ark_payer_claim_pubkey: Some(ark_claim_keypair.public_key().to_string()),
                ark_receive: Some(relay.request.ark_receive.clone()),
                fee_rate_sat_vb: Some(relay.request.fee_rate_sat_vb),
                ark_claim_key_index: Some(ark_claim_key_index),
                btc_claim_key_index: None,
                refund_key_index: None,
                adaptor_secret_hex: Some(secret_key_hex(adaptor_secret.secret_key())),
                btc_secret_nonce: None,
                btc_claim_sighash_hex: None,
                btc_claim_public_nonce_hex: None,
                accepted_ark_transfer_hash_hex: None,
                accepted_ark_input_ids: None,
            };
            store_swap_state(datadir, &state).await?;
            store_relay(&coordinator, &relay).await?;
            output_step(&relay, "btc-fund", &coordinator);
        }
        BtcArkCommand::ArkTransfer {
            coordinator,
            swap,
            allow_unconfirmed,
        } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;
            ensure_relay_not_cancelled(&relay)?;
            if let Some(ark_transfer) = relay.ark_transfer.as_ref() {
                let mut state = load_swap_state(datadir, swap_id, SwapRole::ArkPayer).await?;
                ensure_swap_state_not_cancelled(&state)?;
                state.require_ark_payer_transfer_material()?;
                verify_relay_matches_local_state(wallet, &state, &relay).await?;
                state.verify_accepted_ark_transfer(ark_transfer)?;
                if relay.status == SwapStatus::BtcFunded {
                    relay.status = SwapStatus::ArkTransferred;
                    store_relay(&coordinator, &relay).await?;
                }
                if state.status == SwapStatus::BtcFunded {
                    state.status = SwapStatus::ArkTransferred;
                    store_swap_state(datadir, &state).await?;
                }
                output_step(&relay, next_btc_ark_step(&relay), &coordinator);
                return Ok(());
            }

            let mut state = load_swap_state(datadir, swap_id, SwapRole::ArkPayer).await?;
            ensure_swap_state_not_cancelled(&state)?;
            verify_relay_matches_local_state(wallet, &state, &relay).await?;
            state.require_ark_payer_offer_material()?;
            verify_btc_lock_and_claim_request(wallet, &relay, allow_unconfirmed).await?;
            let terms = relay.terms()?.clone();
            let destination = ark::Address::from_str(&relay.request.ark_receive)
                .context("invalid requested Ark receive address")?;
            wallet
                .validate_arkoor_address(&destination)
                .await
                .context("invalid requested Ark receive address")?;
            let adaptor_secret_hex = state
                .adaptor_secret_hex
                .as_ref()
                .context("Ark payer adaptor secret is missing from local state")?;
            let adaptor_secret = AdaptorSecret::new(secret_key_from_hex(adaptor_secret_hex)?);
            let mut prepared = wallet
                .prepare_btc_ark_transfer(
                    &destination,
                    Amount::from_sat(relay.request.amount_sat),
                    script_from_hex(&terms.btc_payout_script_hex)?,
                    adaptor_secret.point(),
                )
                .await
                .context("failed to prepare adaptor-locked Ark transfer")?;
            prepared.offer.id = swap_id;
            let ark_info = wallet.require_ark_info().await?;
            verify_ark_transfer_offer(
                &prepared.offer,
                swap_id,
                Amount::from_sat(terms.amount_sat),
                &script_from_hex(&terms.btc_payout_script_hex)?,
                destination.policy(),
                ark_info.server_pubkey,
                adaptor_secret.point(),
            )
            .context("prepared Ark transfer does not match offered terms")?;

            relay.ark_transfer = Some(ArkTransferArtifact {
                offer: ArkOfferArtifact::from_offer(&prepared.offer),
                transfer_package_hex: prepared.transfer.serialize_hex(),
            });
            relay.status = SwapStatus::ArkTransferred;

            state.status = SwapStatus::ArkTransferred;
            state.set_accepted_ark_transfer(relay.ark_transfer.as_ref().expect("set above"))?;
            wallet
                .lock_vtxos(&prepared.offer.ark_input_ids, None)
                .await
                .context("failed to lock swapped Ark input VTXOs")?;
            store_swap_state(datadir, &state).await?;
            store_relay(&coordinator, &relay).await?;
            output_step(&relay, next_btc_ark_step(&relay), &coordinator);
        }
        BtcArkCommand::ArkAbort { coordinator, swap } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;

            let exited_vtxos =
                ark_abort_swap_and_exit_inputs(wallet, datadir, &coordinator, &mut relay, swap_id)
                    .await?;
            let exit_required = !exited_vtxos.is_empty();
            let exit_next = if exit_required {
                Some("exit-progress")
            } else {
                None
            };
            let next = exit_next.unwrap_or("done");
            output_json(&serde_json::json!({
                "protocol": "btc-ark",
                "swap_id": relay.swap_id,
                "status": SwapStatus::Cancelled,
                "coordinator": coordinator,
                "next": next,
                "exit_required": exit_required,
                "exit_next": exit_next,
                "exited_vtxos": exited_vtxos,
                "relay": relay,
            }));
        }
        BtcArkCommand::BtcFund { coordinator, swap } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;
            ensure_relay_not_cancelled(&relay)?;
            if relay.claim_request.is_some() {
                let state = load_swap_state(datadir, swap_id, SwapRole::BtcPayer).await?;
                if relay.btc_claim_adaptor.is_none() {
                    state.require_btc_payer_claim_nonce_material()?;
                }
                if let Some(ark_transfer) = relay.ark_transfer.as_ref()
                    && state.accepted_ark_transfer_hash_hex.is_some()
                {
                    state.verify_accepted_ark_transfer(ark_transfer)?;
                }
                output_step(&relay, next_btc_ark_step(&relay), &coordinator);
                return Ok(());
            }
            let mut state = load_swap_state(datadir, swap_id, SwapRole::BtcPayer).await?;
            verify_relay_matches_local_state(wallet, &state, &relay).await?;
            let request = relay.request.clone();
            let terms = relay.terms()?.clone();
            let expected_btc_payout_script = script_from_hex(&terms.btc_payout_script_hex)?;
            let _expected_adaptor_point =
                PublicKey::from_str(&terms.adaptor_point).context("invalid adaptor point")?;
            let network = wallet.network().await?;
            let btc_payout = bitcoin::Address::from_str(&terms.btc_payout_address)
                .context("invalid BTC payout address")?
                .require_network(network)
                .with_context(|| {
                    format!(
                        "BTC payout address is not valid for configured network {}",
                        network
                    )
                })?;
            if btc_payout.script_pubkey() != expected_btc_payout_script {
                bail!("BTC payout address does not match offered payout script");
            }

            onchain
                .sync(&wallet.chain)
                .await
                .context("failed to sync BTC payer on-chain wallet")?;

            let btc_payer_keypair =
                local_keypair(wallet, state.btc_claim_key_index, "BTC claim").await?;
            let btc_lock = expected_btc_lock(wallet, &relay).await?;
            let fee_rate = fee_rate_from_sat_vb(request.fee_rate_sat_vb)?;
            let funding_tx = btc_lock
                .fund_with_onchain(onchain, fee_rate)
                .await
                .context("failed to fund BTC lock")?;
            wallet
                .chain
                .broadcast_tx(&funding_tx)
                .await
                .context("failed to broadcast BTC lock funding transaction")?;
            let funding_txid = funding_tx.compute_txid();
            let funding_vout = funding_tx
                .output
                .iter()
                .position(|output| output.script_pubkey == btc_lock.address.script_pubkey())
                .context("funding transaction did not pay BTC lock")?
                as u32;
            let funding_outpoint = OutPoint::new(funding_txid, funding_vout);
            let claim_tx = build_cooperative_claim_tx(
                funding_outpoint,
                &btc_lock,
                expected_btc_payout_script,
                fee_rate,
            )?;
            let sighash = cooperative_claim_sighash(&claim_tx, &btc_lock)?;
            let adaptor_point =
                PublicKey::from_str(&terms.adaptor_point).context("invalid adaptor point")?;
            let (btc_secret_nonce, btc_public_nonce) =
                musig::adaptor_nonce_pair_with_msg(&btc_payer_keypair, &sighash, adaptor_point)
                    .context("failed to create BTC claim adaptor nonce")?;

            relay.btc_funding = Some(BtcFundingArtifact {
                funding_txid: funding_txid.to_string(),
                funding_vout,
                funding_tx_hex: serialize_hex(&funding_tx),
                lock_address: btc_lock.address.to_string(),
                lock_amount_sat: btc_lock.amount.to_sat(),
            });
            relay.claim_request = Some(BtcClaimRequestArtifact {
                claim_amount_sat: claim_tx.output[0].value.to_sat(),
                claim_tx_hex: serialize_hex(&claim_tx),
                claim_sighash_hex: bytes_hex(&sighash),
                tap_tweak_hex: bytes_hex(&btc_lock.taproot.tap_tweak().to_byte_array()),
                btc_payer_public_nonce_hex: bytes_hex(&btc_public_nonce.serialize()),
            });
            relay.status = SwapStatus::BtcFunded;

            state.status = SwapStatus::BtcFunded;
            state.btc_payout = Some(terms.btc_payout_address.clone());
            state.offer_adaptor_point = Some(terms.adaptor_point.clone());
            state.ark_payer_claim_pubkey = Some(terms.ark_payer_claim_pubkey.clone());
            state.btc_secret_nonce = Some(DangerousSecretNonce::dangerous_from_secret_nonce(
                btc_secret_nonce,
            ));
            state.btc_claim_sighash_hex = Some(bytes_hex(&sighash));
            state.btc_claim_public_nonce_hex = Some(bytes_hex(&btc_public_nonce.serialize()));
            store_swap_state(datadir, &state).await?;
            store_relay(&coordinator, &relay).await?;
            output_step(&relay, next_btc_ark_step(&relay), &coordinator);
        }
        BtcArkCommand::ArkSignBtcClaim {
            coordinator,
            swap,
            allow_unconfirmed,
        } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;
            ensure_relay_not_cancelled(&relay)?;

            if relay.ark_claim_partial.is_none() {
                ark_sign_claim_partial(
                    wallet,
                    datadir,
                    &coordinator,
                    &mut relay,
                    swap_id,
                    allow_unconfirmed,
                )
                .await?;
                output_step(&relay, next_btc_ark_step(&relay), &coordinator);
                return Ok(());
            }

            output_step(&relay, next_btc_ark_step(&relay), &coordinator);
        }
        BtcArkCommand::BtcBuildClaimAdaptor {
            coordinator,
            swap,
            allow_short_ark_transfer_expiry,
        } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;
            ensure_relay_not_cancelled(&relay)?;

            if relay.btc_claim_adaptor.is_none() {
                btc_build_claim_adaptor(
                    wallet,
                    datadir,
                    &coordinator,
                    &mut relay,
                    swap_id,
                    ArkTransferAcceptanceOptions {
                        allow_short_output_expiry: allow_short_ark_transfer_expiry,
                    },
                )
                .await?;
                output_step(&relay, next_btc_ark_step(&relay), &coordinator);
                return Ok(());
            }

            output_step(&relay, next_btc_ark_step(&relay), &coordinator);
        }
        BtcArkCommand::ArkFinalizeBtcClaim {
            coordinator,
            swap,
            allow_unconfirmed,
        } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;
            ensure_relay_not_cancelled(&relay)?;

            let claim_txid = ark_finalize_and_broadcast_claim(
                wallet,
                datadir,
                &mut relay,
                swap_id,
                allow_unconfirmed,
            )
            .await?;
            output_json(&serde_json::json!({
                "protocol": "btc-ark",
                "swap_id": relay.swap_id,
                "status": relay.status,
                "coordinator": coordinator,
                "next": "btc-complete-ark",
                "claim_txid": claim_txid.to_string(),
                "relay": relay,
            }));
        }
        BtcArkCommand::BtcCompleteArk { coordinator, swap } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;

            let state = load_swap_state(datadir, swap_id, SwapRole::BtcPayer).await?;
            if state.status == SwapStatus::ArkCompleted {
                output_step(&relay, "done", &coordinator);
                return Ok(());
            }

            btc_complete_ark_transfer(wallet, datadir, &coordinator, &mut relay, swap_id).await?;
            output_step(&relay, next_btc_ark_step(&relay), &coordinator);
        }
        BtcArkCommand::BtcRefund {
            coordinator,
            swap,
            destination,
        } => {
            let swap_id = SwapId::from_str(&swap).context("swap must be a 32-byte hex swap id")?;
            let mut relay = load_relay(&coordinator).await?;
            relay.require_swap(swap_id)?;

            let refund_txid = btc_refund_lock(
                wallet,
                onchain,
                datadir,
                &coordinator,
                &mut relay,
                swap_id,
                destination,
            )
            .await?;
            output_json(&serde_json::json!({
                "protocol": "btc-ark",
                "swap_id": relay.swap_id,
                "status": relay.status,
                "coordinator": coordinator,
                "next": "done",
                "refund_txid": refund_txid.to_string(),
                "relay": relay,
            }));
        }
    }

    Ok(())
}

async fn ark_abort_swap_and_exit_inputs(
    wallet: &mut Wallet,
    datadir: &Path,
    coordinator: &str,
    relay: &mut RelayFile,
    swap_id: SwapId,
) -> anyhow::Result<Vec<String>> {
    if relay.status == SwapStatus::ArkCompleted {
        bail!("swap already completed; cannot abort Ark transfer");
    }

    let mut state = load_swap_state(datadir, swap_id, SwapRole::ArkPayer).await?;
    verify_relay_matches_local_state(wallet, &state, relay).await?;
    state.require_ark_payer_offer_material()?;

    if state.status == SwapStatus::BtcClaimReady || btc_claim_tx_is_visible(wallet, relay).await? {
        bail!("BTC claim transaction is already visible; adaptor secret may be revealed");
    }

    if let Some(ark_transfer) = relay.ark_transfer.as_ref() {
        state.verify_accepted_ark_transfer(ark_transfer)?;
    }
    let input_ids = if state.accepted_ark_input_ids.is_some() {
        state.accepted_ark_input_ids()?
    } else {
        Vec::new()
    };

    let mut vtxos = Vec::with_capacity(input_ids.len());
    for input_id in &input_ids {
        let wallet_vtxo = wallet
            .get_vtxo_by_id(input_id.clone())
            .await
            .with_context(|| format!("failed to load Ark input VTXO {input_id} for exit"))?;
        vtxos.push(wallet_vtxo.vtxo);
    }

    wallet.exit.get_mut().start_exit_for_vtxos(&vtxos).await?;

    state.status = SwapStatus::Cancelled;
    store_swap_state(datadir, &state).await?;

    relay.status = SwapStatus::Cancelled;
    store_relay(coordinator, relay).await?;

    Ok(input_ids
        .into_iter()
        .map(|input_id| input_id.to_string())
        .collect())
}

async fn btc_claim_tx_is_visible(wallet: &Wallet, relay: &RelayFile) -> anyhow::Result<bool> {
    let Some(claim_request) = relay.claim_request.as_ref() else {
        return Ok(false);
    };
    let claim_tx: Transaction = consensus_deserialize_hex(&claim_request.claim_tx_hex)
        .context("invalid BTC claim transaction")?;
    let claim_txid = claim_tx.compute_txid();
    Ok(wallet
        .chain
        .get_tx(&claim_txid)
        .await
        .context("failed to fetch BTC claim transaction")?
        .is_some())
}

fn ensure_relay_not_cancelled(relay: &RelayFile) -> anyhow::Result<()> {
    if relay.status == SwapStatus::Cancelled {
        bail!("swap is cancelled");
    }
    Ok(())
}

fn ensure_swap_state_not_cancelled(state: &StoredBtcArkSwap) -> anyhow::Result<()> {
    if state.status == SwapStatus::Cancelled {
        bail!("swap is cancelled");
    }
    Ok(())
}

async fn ark_sign_claim_partial(
    wallet: &mut Wallet,
    datadir: &Path,
    coordinator: &str,
    relay: &mut RelayFile,
    swap_id: SwapId,
    allow_unconfirmed: bool,
) -> anyhow::Result<()> {
    let mut state = load_swap_state(datadir, swap_id, SwapRole::ArkPayer).await?;
    ensure_swap_state_not_cancelled(&state)?;
    verify_relay_matches_local_state(wallet, &state, relay).await?;
    state.require_ark_payer_transfer_material()?;
    let ark_transfer = relay
        .ark_transfer
        .as_ref()
        .context("Ark transfer is missing; run ark-transfer first")?;
    state.verify_accepted_ark_transfer(ark_transfer)?;
    let claim_request = relay
        .claim_request
        .as_ref()
        .context("BTC claim request is missing")?;

    verify_btc_lock_and_claim_request(wallet, relay, allow_unconfirmed).await?;

    let ark_keypair = local_keypair(wallet, state.ark_claim_key_index, "Ark claim").await?;
    let btc_payer_pubkey = PublicKey::from_str(&relay.request.btc_payer_claim_pubkey)
        .context("invalid BTC payer claim pubkey")?;
    let btc_public_nonce = public_nonce_from_hex(&claim_request.btc_payer_public_nonce_hex)?;
    let sighash = bytes32_from_hex(&claim_request.claim_sighash_hex)?;
    let tap_tweak = Some(bytes32_from_hex(&claim_request.tap_tweak_hex)?);
    let (ark_public_nonce, ark_partial_sig) = sign_cooperative_claim_partial(
        &ark_keypair,
        btc_payer_pubkey,
        &btc_public_nonce,
        sighash,
        tap_tweak,
    );

    relay.ark_claim_partial = Some(ArkClaimPartialArtifact {
        ark_public_nonce_hex: bytes_hex(&ark_public_nonce.serialize()),
        ark_partial_sig_hex: bytes_hex(&ark_partial_sig.serialize()),
    });
    relay.status = SwapStatus::BtcClaimPartiallySigned;
    store_relay(coordinator, relay).await?;

    state.status = SwapStatus::BtcClaimPartiallySigned;
    store_swap_state(datadir, &state).await?;

    Ok(())
}

async fn ark_finalize_and_broadcast_claim(
    wallet: &mut Wallet,
    datadir: &Path,
    relay: &mut RelayFile,
    swap_id: SwapId,
    allow_unconfirmed: bool,
) -> anyhow::Result<Txid> {
    let mut state = load_swap_state(datadir, swap_id, SwapRole::ArkPayer).await?;
    ensure_swap_state_not_cancelled(&state)?;
    verify_relay_matches_local_state(wallet, &state, relay).await?;
    state.require_ark_payer_transfer_material()?;
    let ark_transfer = relay
        .ark_transfer
        .as_ref()
        .context("Ark transfer is missing; run ark-transfer first")?;
    state.verify_accepted_ark_transfer(ark_transfer)?;
    let verified_funding =
        verify_btc_lock_and_claim_request(wallet, relay, allow_unconfirmed).await?;
    let terms = relay.terms()?.clone();
    let claim_request = relay
        .claim_request
        .as_ref()
        .context("BTC claim request is missing")?;
    let mut claim_tx: Transaction = consensus_deserialize_hex(&claim_request.claim_tx_hex)
        .context("invalid BTC claim transaction")?;
    let claim_txid = claim_tx.compute_txid();
    let already_broadcast = wallet
        .chain
        .get_tx(&claim_txid)
        .await
        .context("failed to fetch BTC claim transaction")?
        .is_some();

    if !already_broadcast {
        let adaptor = relay
            .btc_claim_adaptor
            .as_ref()
            .context("BTC claim adaptor package is missing; run btc-build-claim-adaptor first")?
            .to_package()?;
        adaptor.verify()?;
        if adaptor.sighash != bytes32_from_hex(&claim_request.claim_sighash_hex)? {
            bail!("BTC claim adaptor sighash mismatch");
        }
        let expected_adaptor_point =
            PublicKey::from_str(&terms.adaptor_point).context("invalid adaptor point")?;
        if adaptor.adaptor_point != expected_adaptor_point {
            bail!("BTC claim adaptor point mismatch");
        }
        if adaptor.aggregate_key
            != verified_funding
                .lock
                .taproot
                .output_key()
                .to_x_only_public_key()
        {
            bail!("BTC claim adaptor aggregate key mismatch");
        }
        let adaptor_secret_hex = state
            .adaptor_secret_hex
            .as_ref()
            .context("Ark payer adaptor secret is missing from local state")?;
        let adaptor_secret = AdaptorSecret::new(secret_key_from_hex(adaptor_secret_hex)?);
        let final_sig = adaptor
            .finalize_with_secret(adaptor_secret)
            .context("failed to finalize BTC claim signature")?;
        claim_tx.input[0].witness.push(&final_sig[..]);
        wallet
            .chain
            .broadcast_tx(&claim_tx)
            .await
            .context("failed to broadcast BTC claim transaction")?;
    }

    if state.status != SwapStatus::BtcClaimReady {
        let input_ids = state.accepted_ark_input_ids()?;
        wallet
            .mark_vtxos_as_spent(input_ids)
            .await
            .context("failed to mark swapped Ark inputs as spent")?;

        state.status = SwapStatus::BtcClaimReady;
        store_swap_state(datadir, &state).await?;
    }
    Ok(claim_txid)
}

async fn btc_build_claim_adaptor(
    wallet: &mut Wallet,
    datadir: &Path,
    coordinator: &str,
    relay: &mut RelayFile,
    swap_id: SwapId,
    ark_transfer_acceptance: ArkTransferAcceptanceOptions,
) -> anyhow::Result<()> {
    let mut state = load_swap_state(datadir, swap_id, SwapRole::BtcPayer).await?;
    verify_relay_matches_local_state(wallet, &state, relay).await?;
    state.require_btc_payer_claim_nonce_material()?;
    let ark_transfer = relay
        .ark_transfer
        .as_ref()
        .context("Ark transfer is missing; run ark-transfer first")?;
    if state.accepted_ark_transfer_hash_hex.is_some() {
        state.verify_accepted_ark_transfer(ark_transfer)?;
    } else {
        verify_ark_transfer_for_btc_payer(wallet, relay, swap_id, ark_transfer_acceptance).await?;
        state.set_accepted_ark_transfer(ark_transfer)?;
    }
    let terms = relay.terms()?.clone();
    let claim_request = relay
        .claim_request
        .as_ref()
        .context("BTC claim request is missing")?;
    let ark_partial = relay
        .ark_claim_partial
        .as_ref()
        .context("Ark claim partial is missing; run ark-sign-btc-claim first")?;
    let btc_keypair = local_keypair(wallet, state.btc_claim_key_index, "BTC claim").await?;
    let btc_secret_nonce = state
        .btc_secret_nonce
        .as_ref()
        .context("BTC secret nonce is missing from local state")?
        .to_sec_nonce();
    let claim_sighash = bytes32_from_hex(&claim_request.claim_sighash_hex)?;
    let stored_claim_sighash = state
        .btc_claim_sighash_hex
        .as_ref()
        .context("BTC claim sighash is missing from local state")?;
    if bytes32_from_hex(stored_claim_sighash)? != claim_sighash {
        bail!("BTC claim sighash changed after nonce generation");
    }
    let stored_btc_public_nonce = state
        .btc_claim_public_nonce_hex
        .as_ref()
        .context("BTC claim public nonce is missing from local state")?;
    if stored_btc_public_nonce != &claim_request.btc_payer_public_nonce_hex {
        bail!("BTC claim public nonce changed after nonce generation");
    }
    let btc_public_nonce = public_nonce_from_hex(&claim_request.btc_payer_public_nonce_hex)?;
    let ark_public_nonce = public_nonce_from_hex(&ark_partial.ark_public_nonce_hex)?;
    let ark_partial_sig = partial_sig_from_hex(&ark_partial.ark_partial_sig_hex)?;
    let ark_payer_pubkey = PublicKey::from_str(&terms.ark_payer_claim_pubkey)
        .context("invalid Ark payer claim pubkey")?;
    let adaptor_point =
        PublicKey::from_str(&terms.adaptor_point).context("invalid adaptor point")?;
    let package = build_cooperative_claim_adaptor_package_from_parts(
        &btc_keypair,
        btc_secret_nonce,
        &btc_public_nonce,
        ark_payer_pubkey,
        &ark_public_nonce,
        &ark_partial_sig,
        claim_sighash,
        Some(bytes32_from_hex(&claim_request.tap_tweak_hex)?),
        adaptor_point,
    )?;

    let expected_btc_pubkey = PublicKey::from_str(&relay.request.btc_payer_claim_pubkey)
        .context("invalid accepted BTC payer claim pubkey")?;
    if expected_btc_pubkey != btc_keypair.public_key() {
        bail!("local BTC claim key does not match accepted BTC payer pubkey");
    }

    relay.btc_claim_adaptor = Some(BtcClaimAdaptorArtifact::from_package(&package));
    relay.status = SwapStatus::BtcClaimReady;
    store_relay(coordinator, relay).await?;

    state.status = SwapStatus::BtcClaimReady;
    state.btc_secret_nonce = None;
    store_swap_state(datadir, &state).await
}

async fn btc_refund_lock(
    wallet: &mut Wallet,
    onchain: &mut OnchainWallet,
    datadir: &Path,
    coordinator: &str,
    relay: &mut RelayFile,
    swap_id: SwapId,
    destination: Option<bitcoin::Address<address::NetworkUnchecked>>,
) -> anyhow::Result<Txid> {
    if relay.status == SwapStatus::ArkCompleted {
        bail!("swap already completed; cannot refund BTC lock");
    }

    let mut state = load_swap_state(datadir, swap_id, SwapRole::BtcPayer).await?;
    if state.status == SwapStatus::ArkCompleted {
        bail!("swap already completed; cannot refund BTC lock");
    }
    verify_relay_matches_local_state(wallet, &state, relay).await?;
    if let Some(refund) = relay.btc_refund.as_ref() {
        let refund_txid = refund.refund_txid.clone();
        if relay.status != SwapStatus::Refunded {
            relay.status = SwapStatus::Refunded;
            store_relay(coordinator, relay).await?;
        }
        state.status = SwapStatus::Refunded;
        store_swap_state(datadir, &state).await?;
        return Txid::from_str(&refund_txid).context("invalid stored BTC refund txid");
    }

    let verified_funding = verify_btc_funding(wallet, relay, false).await?;

    if let Some(claim_request) = relay.claim_request.as_ref() {
        let claim_tx: Transaction = consensus_deserialize_hex(&claim_request.claim_tx_hex)
            .context("invalid BTC claim transaction")?;
        let claim_txid = claim_tx.compute_txid();
        if wallet
            .chain
            .get_tx(&claim_txid)
            .await
            .context("failed to fetch BTC claim transaction")?
            .is_some()
        {
            bail!("BTC claim transaction is already visible; cannot refund BTC lock");
        }
    }

    let network = wallet.network().await?;
    let refund_keypair = local_keypair(wallet, state.refund_key_index, "BTC refund").await?;
    let refund_pubkey = XOnlyPublicKey::from_str(&relay.request.btc_refund_pubkey)
        .context("invalid BTC refund pubkey")?;
    if refund_keypair.x_only_public_key().0 != refund_pubkey {
        bail!("local BTC refund key does not match requested refund pubkey");
    }

    let funding_height = wallet
        .chain
        .tx_confirmed(verified_funding.outpoint.txid)
        .await?
        .context("BTC lock funding transaction is not confirmed yet")?;
    let tip = wallet.chain.tip().await?;
    let confirmations = tip.saturating_sub(funding_height).saturating_add(1);
    if !verified_funding.lock.refund_is_mature(confirmations) {
        bail!(
            "BTC refund is not mature yet; funding has {confirmations} confirmation(s), refund delay is {} blocks",
            relay.request.refund_delay_blocks
        );
    }

    let refund_destination = match destination {
        Some(address) => address.require_network(network).with_context(|| {
            format!(
                "refund destination is not valid for configured network {}",
                network
            )
        })?,
        None => {
            onchain
                .sync(&wallet.chain)
                .await
                .context("failed to sync BTC payer on-chain wallet")?;
            onchain.address().await?
        }
    };
    let refund_tx = build_refund_tx(
        verified_funding.outpoint,
        &verified_funding.lock,
        refund_destination.script_pubkey(),
        fee_rate_from_sat_vb(relay.request.fee_rate_sat_vb)?,
    )?;
    let refund_tx = sign_refund_tx(refund_tx, &verified_funding.lock, &refund_keypair)?;
    let refund_txid = refund_tx.compute_txid();
    wallet
        .chain
        .broadcast_tx(&refund_tx)
        .await
        .context("failed to broadcast BTC refund transaction")?;

    relay.btc_refund = Some(BtcRefundArtifact {
        refund_txid: refund_txid.to_string(),
        refund_tx_hex: serialize_hex(&refund_tx),
    });
    relay.status = SwapStatus::Refunded;
    store_relay(coordinator, relay).await?;

    state.status = SwapStatus::Refunded;
    state.btc_secret_nonce = None;
    store_swap_state(datadir, &state).await?;

    Ok(refund_txid)
}

async fn btc_complete_ark_transfer(
    wallet: &mut Wallet,
    datadir: &Path,
    coordinator: &str,
    relay: &mut RelayFile,
    swap_id: SwapId,
) -> anyhow::Result<()> {
    let mut state = load_swap_state(datadir, swap_id, SwapRole::BtcPayer).await?;
    verify_relay_matches_local_state(wallet, &state, relay).await?;
    let ark_transfer = relay
        .ark_transfer
        .as_ref()
        .context("Ark transfer is missing")?;
    state.verify_accepted_ark_transfer(ark_transfer)?;
    let transfer = ark::arkoor::package::TransferableAdaptorArkoorPackage::deserialize_hex(
        &ark_transfer.transfer_package_hex,
    )
    .context("invalid Ark transfer package")?;
    let adaptor = relay
        .btc_claim_adaptor
        .as_ref()
        .context("BTC claim adaptor package is missing")?
        .to_package()?;
    let claim_request = relay
        .claim_request
        .as_ref()
        .context("BTC claim request is missing")?;
    let expected_claim_tx: Transaction = consensus_deserialize_hex(&claim_request.claim_tx_hex)
        .context("invalid BTC claim transaction")?;
    let claim_txid = expected_claim_tx.compute_txid();
    let observed_claim_tx = wallet
        .chain
        .get_tx(&claim_txid)
        .await
        .context("failed to fetch BTC claim transaction")?
        .context("BTC claim transaction is not visible to chain source yet")?;
    let mut observed_without_witness = observed_claim_tx.clone();
    for input in &mut observed_without_witness.input {
        input.witness = bitcoin::Witness::new();
    }
    if observed_without_witness != expected_claim_tx {
        bail!("observed BTC claim transaction does not match expected claim transaction");
    }
    let final_sig_bytes = observed_claim_tx
        .input
        .first()
        .and_then(|input| input.witness.nth(0))
        .context("observed BTC claim transaction has no key-spend signature")?;
    if final_sig_bytes.len() != 64 {
        bail!("observed BTC claim signature is not a default Schnorr signature");
    }
    let final_sig = schnorr::Signature::from_slice(final_sig_bytes)
        .context("observed BTC claim signature is invalid")?;
    let recovered_secret = adaptor
        .recover_secret(final_sig)
        .context("final BTC signature did not reveal expected adaptor secret")?;
    let _received_vtxos = wallet
        .complete_btc_ark_transfer(transfer, recovered_secret)
        .await
        .context("failed to import finalized Ark VTXO package")?;

    relay.status = SwapStatus::ArkCompleted;
    store_relay(coordinator, relay).await?;

    state.status = SwapStatus::ArkCompleted;
    store_swap_state(datadir, &state).await
}

async fn verify_relay_matches_local_state(
    wallet: &Wallet,
    state: &StoredBtcArkSwap,
    relay: &RelayFile,
) -> anyhow::Result<()> {
    if let Some(expected_amount) = state.amount_sat
        && relay.request.amount_sat != expected_amount
    {
        bail!("relay amount changed after local swap state was created");
    }
    if let Some(expected_amount) = state.amount_sat
        && let Some(terms) = &relay.terms
        && terms.amount_sat != expected_amount
    {
        bail!("relay Ark transfer amount changed after local swap state was created");
    }

    if let Some(expected_ark_receive) = &state.ark_receive
        && relay.request.ark_receive != *expected_ark_receive
    {
        bail!("relay Ark receive address changed after local swap state was created");
    }

    if let Some(expected_fee_rate) = state.fee_rate_sat_vb
        && relay.request.fee_rate_sat_vb != expected_fee_rate
    {
        bail!("relay fee rate changed after local swap state was created");
    }

    if let Some(btc_claim_key_index) = state.btc_claim_key_index {
        let keypair = local_keypair(wallet, Some(btc_claim_key_index), "BTC claim").await?;
        if relay.request.btc_payer_claim_pubkey != keypair.public_key().to_string() {
            bail!("relay BTC payer claim pubkey does not match local key");
        }
    }

    if let Some(refund_key_index) = state.refund_key_index {
        let keypair = local_keypair(wallet, Some(refund_key_index), "BTC refund").await?;
        if relay.request.btc_refund_pubkey != keypair.x_only_public_key().0.to_string() {
            bail!("relay BTC refund pubkey does not match local key");
        }
    }

    if let Some(expected_payout) = &state.btc_payout {
        let terms = relay
            .terms
            .as_ref()
            .context("relay Ark transfer terms are missing from local swap state")?;
        let network = wallet.network().await?;
        let expected_payout = bitcoin::Address::from_str(expected_payout)
            .context("stored BTC payout address is invalid")?
            .require_network(network)
            .with_context(|| {
                format!(
                    "stored BTC payout address is not valid for configured network {}",
                    network
                )
            })?;
        if terms.btc_payout_address != expected_payout.to_string()
            || terms.btc_payout_script_hex != bytes_hex(expected_payout.script_pubkey().as_bytes())
        {
            bail!("relay BTC payout changed after local swap state was created");
        }
    }

    if let Some(expected_adaptor_point) = &state.offer_adaptor_point {
        let terms = relay
            .terms
            .as_ref()
            .context("relay Ark transfer terms are missing from local swap state")?;
        if terms.adaptor_point != *expected_adaptor_point {
            bail!("relay adaptor point changed after local swap state was created");
        }
    } else if let Some(secret_hex) = &state.adaptor_secret_hex {
        let terms = relay
            .terms
            .as_ref()
            .context("relay Ark transfer terms are missing from local swap state")?;
        let secret = AdaptorSecret::new(secret_key_from_hex(secret_hex)?);
        if terms.adaptor_point != secret.point().to_string() {
            bail!("relay adaptor point does not match local adaptor secret");
        }
    }

    if let Some(expected_claim_pubkey) = &state.ark_payer_claim_pubkey {
        let terms = relay
            .terms
            .as_ref()
            .context("relay Ark transfer terms are missing from local swap state")?;
        if terms.ark_payer_claim_pubkey != *expected_claim_pubkey {
            bail!("relay Ark payer claim pubkey changed after local swap state was created");
        }
    } else if state.ark_claim_key_index.is_some() {
        let terms = relay
            .terms
            .as_ref()
            .context("relay Ark transfer terms are missing from local swap state")?;
        let keypair = local_keypair(wallet, state.ark_claim_key_index, "Ark claim").await?;
        if terms.ark_payer_claim_pubkey != keypair.public_key().to_string() {
            bail!("relay Ark payer claim pubkey does not match local key");
        }
    }

    Ok(())
}

async fn verify_ark_transfer_for_btc_payer(
    wallet: &Wallet,
    relay: &RelayFile,
    swap_id: SwapId,
    acceptance: ArkTransferAcceptanceOptions,
) -> anyhow::Result<()> {
    let terms = relay.terms()?.clone();
    let ark_transfer = relay
        .ark_transfer
        .as_ref()
        .context("Ark transfer is missing; run ark-transfer first")?;
    let offer = ark_transfer.offer.to_offer()?;
    let transfer = ark::arkoor::package::TransferableAdaptorArkoorPackage::deserialize_hex(
        &ark_transfer.transfer_package_hex,
    )
    .context("invalid Ark transfer package")?;
    let destination = ark::Address::from_str(&relay.request.ark_receive)
        .context("invalid requested Ark receive address")?;
    wallet
        .validate_arkoor_address(&destination)
        .await
        .context("invalid requested Ark receive address")?;
    let ark_info = wallet.require_ark_info().await?;
    verify_ark_transfer_offer(
        &offer,
        swap_id,
        Amount::from_sat(terms.amount_sat),
        &script_from_hex(&terms.btc_payout_script_hex)?,
        destination.policy(),
        ark_info.server_pubkey,
        PublicKey::from_str(&terms.adaptor_point).context("invalid adaptor point")?,
    )
    .context("Ark transfer does not match offered terms")?;

    let current_height = wallet.chain.tip().await?;
    let minimum_output_expiry_height =
        current_height.saturating_add(u32::from(relay.request.refund_delay_blocks));
    verify_ark_transfer_is_safe_to_accept(
        &offer,
        &transfer,
        minimum_output_expiry_height,
        acceptance,
    )?;

    Ok(())
}

struct VerifiedBtcFunding {
    lock: BtcLockContract,
    outpoint: OutPoint,
}

async fn expected_btc_lock(wallet: &Wallet, relay: &RelayFile) -> anyhow::Result<BtcLockContract> {
    let terms = relay.terms()?;
    Ok(BtcLockContract::new(
        Amount::from_sat(terms.amount_sat),
        wallet.network().await?,
        PublicKey::from_str(&relay.request.btc_payer_claim_pubkey)
            .context("invalid BTC payer claim pubkey")?,
        PublicKey::from_str(&terms.ark_payer_claim_pubkey)
            .context("invalid Ark payer claim pubkey")?,
        XOnlyPublicKey::from_str(&relay.request.btc_refund_pubkey)
            .context("invalid BTC refund pubkey")?,
        relay.request.refund_delay_blocks,
    ))
}

async fn verify_btc_funding(
    wallet: &Wallet,
    relay: &RelayFile,
    allow_unconfirmed: bool,
) -> anyhow::Result<VerifiedBtcFunding> {
    let funding = relay
        .btc_funding
        .as_ref()
        .context("BTC funding is missing")?;
    let btc_lock = expected_btc_lock(wallet, relay).await?;

    if funding.lock_address != btc_lock.address.to_string() {
        bail!("BTC lock address mismatch");
    }
    if funding.lock_amount_sat != btc_lock.amount.to_sat() {
        bail!("BTC lock amount mismatch");
    }

    let funding_txid = Txid::from_str(&funding.funding_txid).context("invalid funding txid")?;
    let funding_tx = wallet
        .chain
        .get_tx(&funding_txid)
        .await
        .context("failed to fetch BTC lock funding transaction")?
        .context("BTC lock funding transaction is not visible to chain source")?;
    let funding_out = funding_tx
        .output
        .get(funding.funding_vout as usize)
        .context("BTC lock funding vout is out of range")?;
    if *funding_out != btc_lock.txout() {
        bail!("BTC funding output does not match expected lock contract");
    }

    if !allow_unconfirmed && wallet.chain.tx_confirmed(funding_txid).await?.is_none() {
        bail!(
            "BTC lock is not confirmed yet; wait for confirmation or pass --allow-unconfirmed for a local POC"
        );
    }

    Ok(VerifiedBtcFunding {
        lock: btc_lock,
        outpoint: OutPoint::new(funding_txid, funding.funding_vout),
    })
}

fn verify_claim_request(
    relay: &RelayFile,
    btc_lock: &BtcLockContract,
    funding_outpoint: OutPoint,
) -> anyhow::Result<Transaction> {
    let terms = relay.terms()?;
    let claim_request = relay
        .claim_request
        .as_ref()
        .context("BTC claim request is missing")?;
    let claim_tx: Transaction = consensus_deserialize_hex(&claim_request.claim_tx_hex)
        .context("invalid BTC claim transaction")?;
    let expected_claim_tx = build_cooperative_claim_tx(
        funding_outpoint,
        btc_lock,
        script_from_hex(&terms.btc_payout_script_hex)?,
        fee_rate_from_sat_vb(relay.request.fee_rate_sat_vb)?,
    )?;
    if claim_tx != expected_claim_tx {
        bail!("BTC claim transaction does not match expected claim transaction");
    }
    let expected_claim_amount = expected_claim_tx
        .output
        .first()
        .context("expected BTC claim transaction has no outputs")?
        .value
        .to_sat();
    if claim_request.claim_amount_sat != expected_claim_amount {
        bail!("BTC claim amount mismatch");
    }
    if bytes32_from_hex(&claim_request.tap_tweak_hex)?
        != btc_lock.taproot.tap_tweak().to_byte_array()
    {
        bail!("BTC claim tap tweak mismatch");
    }
    let expected_sighash = cooperative_claim_sighash(&expected_claim_tx, btc_lock)?;
    if expected_sighash != bytes32_from_hex(&claim_request.claim_sighash_hex)? {
        bail!("BTC claim sighash mismatch");
    }

    Ok(claim_tx)
}

async fn verify_btc_lock_and_claim_request(
    wallet: &Wallet,
    relay: &RelayFile,
    allow_unconfirmed: bool,
) -> anyhow::Result<VerifiedBtcFunding> {
    let verified_funding = verify_btc_funding(wallet, relay, allow_unconfirmed).await?;
    verify_claim_request(relay, &verified_funding.lock, verified_funding.outpoint)?;
    Ok(verified_funding)
}

fn verify_ark_transfer_is_safe_to_accept(
    offer: &ArkOffer,
    transfer: &ark::arkoor::package::TransferableAdaptorArkoorPackage,
    minimum_output_expiry_height: bitcoin_ext::BlockHeight,
    acceptance: ArkTransferAcceptanceOptions,
) -> anyhow::Result<()> {
    verify_ark_transfer_before_acceptance_with_options(
        offer,
        transfer,
        minimum_output_expiry_height,
        acceptance,
    )
    .context("Ark transfer package is not safe to accept")
}

async fn local_keypair(
    wallet: &Wallet,
    index: Option<u32>,
    label: &str,
) -> anyhow::Result<Keypair> {
    let index = index.with_context(|| format!("{label} key index is missing from local state"))?;
    wallet
        .peek_keypair(index)
        .await
        .with_context(|| format!("failed to derive local {label} keypair at index {index}"))
}

fn output_step(relay: &RelayFile, next: &str, coordinator: &str) {
    output_json(&serde_json::json!({
        "protocol": "btc-ark",
        "swap_id": relay.swap_id,
        "status": relay.status,
        "coordinator": coordinator,
        "next": next,
        "relay": relay,
    }));
}

fn next_btc_ark_step(relay: &RelayFile) -> &'static str {
    if relay.status == SwapStatus::ArkCompleted
        || relay.status == SwapStatus::Refunded
        || relay.status == SwapStatus::Cancelled
    {
        "done"
    } else if relay.terms.is_none() {
        "ark-offer"
    } else if relay.claim_request.is_none() {
        "btc-fund"
    } else if relay.ark_transfer.is_none() {
        "ark-transfer"
    } else if relay.ark_claim_partial.is_none() {
        "ark-sign-btc-claim"
    } else if relay.btc_claim_adaptor.is_none() {
        "btc-build-claim-adaptor"
    } else {
        "ark-finalize-btc-claim"
    }
}
