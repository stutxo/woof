use std::{collections::BTreeSet, path::PathBuf, str::FromStr, sync::Arc};

use ark::musig::AdaptorSecret;
use ark_testing::{Bark, Captaind, TestContext, btc, sat};
use bark::swap::btc_ark::{
    BtcLockContract, build_cooperative_claim_adaptor_package, verify_ark_transfer_before_acceptance,
};
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    consensus::encode::{deserialize_hex, serialize_hex},
    hashes::Hash as _,
    secp256k1::{Keypair, SecretKey, rand},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
};
use bitcoincore_rpc::RpcApi;
use serde_json::Value;

#[tokio::test]
async fn happy_path_swaps_btc_for_ark_vtxo() {
    let ctx = TestContext::new("bark/happy_path_swaps_btc_for_ark_vtxo").await;
    let srv = ctx.captaind("server").funded(btc(10)).create().await;
    let ark_payer = ctx
        .bark("ark_payer", &srv)
        .funded(sat(120_000))
        .create()
        .await;
    let btc_payer = ctx
        .bark("btc_payer", &srv)
        .funded(sat(300_000))
        .create()
        .await;

    ark_payer
        .board_and_confirm_and_register(&ctx, sat(80_000))
        .await;
    assert_eq!(sat(80_000), ark_payer.spendable_balance().await);

    let btc_payer_ark_receive = ark::Address::from_str(btc_payer.address().await.trim())
        .expect("BTC payer Ark receive address");
    let ark_payer_btc_payout = ark_payer.get_onchain_address().await;
    let ark_payer_btc_before = ark_payer.onchain_balance().await;

    // BtcPayer starts with its Ark receive address and BTC claim/refund keys.
    let btc_payer_claim_key = Keypair::new(&ark::SECP, &mut rand::thread_rng());
    let ark_payer_claim_key = Keypair::new(&ark::SECP, &mut rand::thread_rng());

    // ArkPayer replies with public terms: the adaptor point `T`, claim key,
    // BTC payout, and amount. No Ark VTXO is spent before the BTC lock exists.
    let adaptor_secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));

    // BtcPayer funds the Taproot BTC lock from the Bark on-chain wallet.
    let swap_amount = sat(80_000);
    let btc_lock = BtcLockContract::new(
        swap_amount,
        Network::Regtest,
        btc_payer_claim_key.public_key(),
        ark_payer_claim_key.public_key(),
        btc_payer_claim_key.x_only_public_key().0,
        6,
    );

    let lock_address = btc_lock.address.to_string();
    let lock_amount = swap_amount.to_string();
    let funding: ark_testing::bark::json::cli::onchain::Send = btc_payer
        .run_json(["onchain", "send", &lock_address, &lock_amount, "--verbose"])
        .await;
    ctx.generate_blocks(1).await;

    let rpc = ctx.bitcoind().sync_client();
    let funding_tx = rpc
        .get_raw_transaction(&funding.txid, None)
        .expect("BTC lock funding tx is known to bitcoind");
    let funding_vout = funding_tx
        .output
        .iter()
        .position(|output| output.script_pubkey == btc_lock.address.script_pubkey())
        .expect("funding tx pays the BTC lock") as u32;
    let funding_outpoint = OutPoint::new(funding.txid, funding_vout);

    // Once the BTC lock is confirmed, ArkPayer builds the adaptor-locked Ark
    // transfer package.
    let prepared = {
        let ark_payer_wallet = ark_payer.client().await;
        ark_payer_wallet
            .prepare_btc_ark_transfer(
                &btc_payer_ark_receive,
                swap_amount,
                ark_payer_btc_payout.script_pubkey(),
                adaptor_secret.point(),
            )
            .await
            .expect("ArkPayer prepares adaptor-locked Ark transfer")
    };
    let offer = prepared.offer;
    let transfer = prepared.transfer;

    let current_height = ctx.bitcoind().get_block_count().await as bitcoin_ext::BlockHeight;
    verify_ark_transfer_before_acceptance(&offer, &transfer, current_height + 6)
        .expect("Ark package is safe to accept");

    // BtcPayer publishes a BTC claim adaptor package locked to the same `T`.
    let btc_claim_amount = offer.amount.checked_sub(sat(1_000)).expect("claim fee");
    let mut btc_claim_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: btc_claim_amount,
            script_pubkey: offer.btc_payout_script.clone(),
        }],
    };
    let btc_claim_sighash = SighashCache::new(&btc_claim_tx)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&[btc_lock.txout()]),
            TapSighashType::Default,
        )
        .expect("BTC claim sighash");
    let btc_claim_adaptor = build_cooperative_claim_adaptor_package(
        &btc_payer_claim_key,
        &ark_payer_claim_key,
        btc_claim_sighash.to_byte_array(),
        Some(btc_lock.taproot.tap_tweak().to_byte_array()),
        offer.adaptor_point,
    )
    .expect("BTC claim adaptor package");

    // ArkPayer waits for the BTC lock, releases `t` by finalizing the BTC claim,
    // and broadcasts the payout transaction.
    let final_btc_claim_sig = btc_claim_adaptor
        .finalize_with_secret(adaptor_secret)
        .expect("ArkPayer finalizes BTC claim with t");
    btc_claim_tx.input[0].witness.push(&final_btc_claim_sig[..]);
    let btc_claim_txid = rpc
        .send_raw_transaction(&btc_claim_tx)
        .expect("BTC claim broadcasts");
    ctx.generate_blocks(1).await;
    let observed_claim_tx = rpc
        .get_raw_transaction(&btc_claim_txid, None)
        .expect("BTC claim is visible on chain");
    let observed_final_sig = observed_claim_tx.input[0]
        .witness
        .nth(0)
        .and_then(|sig| bitcoin::secp256k1::schnorr::Signature::from_slice(sig).ok())
        .expect("BTC claim reveals a key-spend signature");

    // BtcPayer extracts `t` from the final BTC signature and completes the Ark
    // VTXO transfer locally.
    let recovered_secret = btc_claim_adaptor
        .recover_secret(observed_final_sig)
        .expect("BtcPayer extracts t from final BTC claim signature");
    assert_eq!(recovered_secret.secret_key(), adaptor_secret.secret_key());

    let btc_payer_wallet = btc_payer.client().await;
    let received_vtxos = btc_payer_wallet
        .complete_btc_ark_transfer(transfer, recovered_secret)
        .await
        .expect("BtcPayer imports finalized Ark VTXO");
    let received_amount = received_vtxos.iter().map(|vtxo| vtxo.amount()).sum();
    assert_eq!(offer.amount, received_amount);
    assert_eq!(
        offer.amount,
        btc_payer_wallet.balance().await.unwrap().spendable,
    );

    {
        let ark_payer_wallet = ark_payer.client().await;
        ark_payer_wallet
            .mark_vtxos_as_spent(offer.ark_input_ids.clone())
            .await
            .expect("ArkPayer records swapped Ark inputs as spent");
        assert_eq!(sat(0), ark_payer_wallet.balance().await.unwrap().spendable);
    }

    let ark_payer_btc_after = ark_payer.onchain_balance().await;
    assert!(ark_payer_btc_after >= ark_payer_btc_before + btc_claim_amount);
}

struct CliBtcArkSwap {
    ctx: TestContext,
    _srv: Arc<Captaind>,
    ark_payer: Bark,
    btc_payer: Bark,
    relay: PathBuf,
    coordinator: String,
    swap_id: String,
    ark_payer_btc_before: Amount,
}

async fn prepare_cli_btc_ark_funded_swap(test_name: &str, relay_file: &str) -> CliBtcArkSwap {
    let ctx = TestContext::new(test_name).await;
    let srv = ctx.captaind("server").funded(btc(10)).create().await;
    let ark_payer = ctx
        .bark("ark_payer", &srv)
        .funded(sat(120_000))
        .create()
        .await;
    let btc_payer = ctx
        .bark("btc_payer", &srv)
        .funded(sat(300_000))
        .create()
        .await;

    let swap_amount = sat(80_000);
    ark_payer
        .board_and_confirm_and_register(&ctx, swap_amount)
        .await;
    assert_eq!(swap_amount, ark_payer.spendable_balance().await);

    let relay = ctx.datadir.join(relay_file);
    let coordinator = relay.display().to_string();
    let amount_arg = swap_amount.to_string();
    let btc_payout = ark_payer.get_onchain_address().await.to_string();
    let ark_receive = btc_payer.address().await.trim().to_owned();
    let ark_payer_btc_before = ark_payer.onchain_balance().await;

    let requested: Value = btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-request",
            "--coordinator",
            &coordinator,
            "--amount",
            &amount_arg,
            "--ark-receive",
            &ark_receive,
            "--fee-rate",
            "1",
            "--refund-delay",
            "6",
        ])
        .await;
    assert_eq!("Requested", requested["status"].as_str().unwrap());
    assert_eq!("ark-offer", requested["next"].as_str().unwrap());
    let swap_id = requested["swap_id"].as_str().unwrap().to_owned();

    let offered: Value = ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-offer",
            "--coordinator",
            &coordinator,
            "--swap",
            &swap_id,
            "--btc-payout",
            &btc_payout,
        ])
        .await;
    assert_eq!("Offered", offered["status"].as_str().unwrap());
    assert_eq!("btc-fund", offered["next"].as_str().unwrap());
    assert_eq!(swap_amount, ark_payer.spendable_balance().await);

    let funded: Value = btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-fund",
            "--coordinator",
            &coordinator,
            "--swap",
            &swap_id,
        ])
        .await;
    assert_eq!("BtcFunded", funded["status"].as_str().unwrap());
    assert_eq!("ark-transfer", funded["next"].as_str().unwrap());

    CliBtcArkSwap {
        ctx,
        _srv: srv,
        ark_payer,
        btc_payer,
        relay,
        coordinator,
        swap_id,
        ark_payer_btc_before,
    }
}

async fn prepare_cli_btc_ark_swap(test_name: &str, relay_file: &str) -> CliBtcArkSwap {
    let setup = prepare_cli_btc_ark_funded_swap(test_name, relay_file).await;

    setup.ctx.generate_blocks(1).await;

    let transferred: Value = setup
        .ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-transfer",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("BtcFunded", transferred["status"].as_str().unwrap());
    assert_eq!("ark-sign-btc-claim", transferred["next"].as_str().unwrap());

    setup
}

#[tokio::test]
async fn cli_happy_path_swaps_btc_for_ark_vtxo() {
    let setup = prepare_cli_btc_ark_swap(
        "bark/cli_happy_path_swaps_btc_for_ark_vtxo",
        "btc-ark-cli-relay.json",
    )
    .await;
    let swap_amount = sat(80_000);

    let ark_partial: Value = setup
        .ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-sign-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("BtcFunded", ark_partial["status"].as_str().unwrap());
    assert_eq!(
        "btc-build-claim-adaptor",
        ark_partial["next"].as_str().unwrap()
    );

    let repeated_ark_partial: Value = setup
        .ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-sign-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!(
        "BtcFunded",
        repeated_ark_partial["status"].as_str().unwrap()
    );
    assert_eq!(
        "btc-build-claim-adaptor",
        repeated_ark_partial["next"].as_str().unwrap()
    );

    let btc_adaptor: Value = setup
        .btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-build-claim-adaptor",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("BtcClaimReady", btc_adaptor["status"].as_str().unwrap());
    assert_eq!(
        "ark-finalize-btc-claim",
        btc_adaptor["next"].as_str().unwrap()
    );
    let btc_state_path = setup
        .btc_payer
        .datadir()
        .join("swap")
        .join(format!("btc-ark-{}-btc-payer.json", setup.swap_id));
    let btc_state: Value =
        serde_json::from_str(&tokio::fs::read_to_string(btc_state_path).await.unwrap()).unwrap();
    assert!(btc_state["btc_secret_nonce"].is_null());
    assert_eq!(
        btc_adaptor["relay"]["claim_request"]["claim_sighash_hex"],
        btc_state["btc_claim_sighash_hex"],
    );
    assert_eq!(
        btc_adaptor["relay"]["claim_request"]["btc_payer_public_nonce_hex"],
        btc_state["btc_claim_public_nonce_hex"],
    );

    let final_claim: Value = setup
        .ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-finalize-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("BtcClaimReady", final_claim["status"].as_str().unwrap());
    assert_eq!("btc-complete-ark", final_claim["next"].as_str().unwrap());
    assert!(final_claim["claim_txid"].as_str().is_some());
    assert!(
        !final_claim["relay"]
            .as_object()
            .unwrap()
            .contains_key("final_claim")
    );

    let repeated_final_claim: Value = setup
        .ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-finalize-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!(
        final_claim["claim_txid"].as_str().unwrap(),
        repeated_final_claim["claim_txid"].as_str().unwrap()
    );
    assert_eq!(
        "BtcClaimReady",
        repeated_final_claim["status"].as_str().unwrap()
    );
    assert_eq!(
        "btc-complete-ark",
        repeated_final_claim["next"].as_str().unwrap()
    );

    setup.ctx.generate_blocks(1).await;

    let done: Value = setup
        .btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-complete-ark",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("ArkCompleted", done["status"].as_str().unwrap());
    assert_eq!("done", done["next"].as_str().unwrap());
    assert!(
        !done["relay"]
            .as_object()
            .unwrap()
            .contains_key("final_claim")
    );

    assert_eq!(swap_amount, setup.btc_payer.spendable_balance().await);
    assert_eq!(sat(0), setup.ark_payer.spendable_balance().await);
    assert!(setup.ark_payer.onchain_balance().await > setup.ark_payer_btc_before);

    let relay_text = tokio::fs::read_to_string(setup.relay).await.unwrap();
    assert!(!relay_text.contains("mnemonic"));
    assert!(!relay_text.contains("adaptor_secret"));
    assert!(!relay_text.contains("secret_nonce"));
}

#[tokio::test]
async fn cli_btc_refund_after_delay_when_ark_transfer_missing() {
    let setup = prepare_cli_btc_ark_funded_swap(
        "bark/cli_btc_refund_after_delay_when_ark_transfer_missing",
        "btc-ark-cli-refund-relay.json",
    )
    .await;

    setup.ctx.generate_blocks(1).await;
    let early_err = setup
        .btc_payer
        .try_run([
            "swap",
            "btc-ark",
            "btc-refund",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await
        .expect_err("BTC refund must wait for the CSV delay");
    assert!(
        early_err
            .to_string()
            .contains("BTC refund is not mature yet"),
        "{early_err:#}",
    );

    setup.ctx.generate_blocks(6).await;
    let refund: Value = setup
        .btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-refund",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("Refunded", refund["status"].as_str().unwrap());
    assert_eq!("done", refund["next"].as_str().unwrap());
    assert!(refund["refund_txid"].as_str().is_some());
    assert!(
        refund["relay"]["btc_refund"]["refund_tx_hex"]
            .as_str()
            .is_some()
    );

    let repeated_refund: Value = setup
        .btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-refund",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!(
        refund["refund_txid"].as_str().unwrap(),
        repeated_refund["refund_txid"].as_str().unwrap()
    );
    assert_eq!("Refunded", repeated_refund["status"].as_str().unwrap());
    assert_eq!("done", repeated_refund["next"].as_str().unwrap());
}

#[tokio::test]
async fn cli_ark_abort_after_transfer_exits_inputs_and_allows_btc_refund() {
    let setup = prepare_cli_btc_ark_swap(
        "bark/cli_ark_abort_after_transfer_exits_inputs_and_allows_btc_refund",
        "btc-ark-cli-abort-relay.json",
    )
    .await;

    let relay_before: Value =
        serde_json::from_str(&tokio::fs::read_to_string(&setup.relay).await.unwrap()).unwrap();
    let input_ids = relay_before["ark_transfer"]["offer"]["ark_input_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert!(!input_ids.is_empty());
    assert_eq!(sat(0), setup.ark_payer.spendable_balance_no_sync().await);

    let ark_partial: Value = setup
        .ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-sign-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("BtcFunded", ark_partial["status"].as_str().unwrap());
    assert_eq!(
        "btc-build-claim-adaptor",
        ark_partial["next"].as_str().unwrap()
    );

    let btc_adaptor: Value = setup
        .btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-build-claim-adaptor",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("BtcClaimReady", btc_adaptor["status"].as_str().unwrap());
    assert_eq!(
        "ark-finalize-btc-claim",
        btc_adaptor["next"].as_str().unwrap()
    );

    let abort: Value = setup
        .ark_payer
        .run_json([
            "swap",
            "btc-ark",
            "ark-abort",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("Cancelled", abort["status"].as_str().unwrap());
    assert_eq!("exit-progress", abort["next"].as_str().unwrap());
    assert!(abort["exit_required"].as_bool().unwrap());
    assert_eq!("exit-progress", abort["exit_next"].as_str().unwrap());
    let exited_vtxos = abort["exited_vtxos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(input_ids, exited_vtxos);
    assert_eq!(sat(0), setup.ark_payer.spendable_balance_no_sync().await);

    let exits = setup.ark_payer.list_exits_no_sync().await;
    let exit_ids = exits
        .iter()
        .map(|exit| exit.vtxo_id.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(input_ids, exit_ids);

    let err = setup
        .ark_payer
        .try_run([
            "swap",
            "btc-ark",
            "ark-finalize-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await
        .expect_err("Alice must not be able to reveal the adaptor secret after aborting");
    assert!(err.to_string().contains("swap is cancelled"), "{err:#}");

    let err = setup
        .btc_payer
        .try_run([
            "swap",
            "btc-ark",
            "btc-complete-ark",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await
        .expect_err("Bob cannot finalize Ark without the revealed adaptor secret");
    assert!(
        err.to_string()
            .contains("BTC claim transaction is not visible"),
        "{err:#}",
    );

    setup.ctx.generate_blocks(6).await;
    let refund: Value = setup
        .btc_payer
        .run_json([
            "swap",
            "btc-ark",
            "btc-refund",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;
    assert_eq!("Refunded", refund["status"].as_str().unwrap());
    assert_eq!("done", refund["next"].as_str().unwrap());
    assert!(refund["refund_txid"].as_str().is_some());
}

#[tokio::test]
async fn cli_ark_sign_btc_claim_rejects_tampered_btc_claim_tx() {
    let setup = prepare_cli_btc_ark_swap(
        "bark/cli_ark_sign_btc_claim_rejects_tampered_btc_claim_tx",
        "btc-ark-cli-tampered-claim-relay.json",
    )
    .await;

    let mut relay_json: Value =
        serde_json::from_str(&tokio::fs::read_to_string(&setup.relay).await.unwrap()).unwrap();
    let claim_request = relay_json["claim_request"].as_object_mut().unwrap();
    let mut claim_tx: Transaction =
        deserialize_hex(claim_request["claim_tx_hex"].as_str().unwrap()).unwrap();
    claim_tx.output[0].value = claim_tx.output[0].value.checked_sub(sat(1_000)).unwrap();
    claim_request.insert("claim_tx_hex".to_owned(), serialize_hex(&claim_tx).into());
    claim_request.insert(
        "claim_amount_sat".to_owned(),
        claim_tx.output[0].value.to_sat().into(),
    );
    tokio::fs::write(
        &setup.relay,
        serde_json::to_vec_pretty(&relay_json).unwrap(),
    )
    .await
    .unwrap();

    let err = setup
        .ark_payer
        .try_run([
            "swap",
            "btc-ark",
            "ark-sign-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await
        .expect_err("tampered BTC claim tx must be rejected");
    assert!(
        err.to_string()
            .contains("BTC claim transaction does not match expected claim transaction"),
        "{err:#}",
    );
}

#[tokio::test]
async fn cli_btc_build_claim_adaptor_rejects_changed_claim_sighash() {
    let setup = prepare_cli_btc_ark_swap(
        "bark/cli_btc_build_claim_adaptor_rejects_changed_claim_sighash",
        "btc-ark-cli-tampered-sighash-relay.json",
    )
    .await;
    setup
        .ark_payer
        .run_json::<Value, _, _>([
            "swap",
            "btc-ark",
            "ark-sign-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;

    let mut relay_json: Value =
        serde_json::from_str(&tokio::fs::read_to_string(&setup.relay).await.unwrap()).unwrap();
    relay_json["claim_request"]["claim_sighash_hex"] =
        "0000000000000000000000000000000000000000000000000000000000000000".into();
    tokio::fs::write(
        &setup.relay,
        serde_json::to_vec_pretty(&relay_json).unwrap(),
    )
    .await
    .unwrap();

    let err = setup
        .btc_payer
        .try_run([
            "swap",
            "btc-ark",
            "btc-build-claim-adaptor",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await
        .expect_err("changed BTC claim sighash must be rejected");
    assert!(
        err.to_string()
            .contains("BTC claim sighash changed after nonce generation"),
        "{err:#}",
    );
}

#[tokio::test]
async fn cli_btc_build_claim_adaptor_rejects_changed_claim_public_nonce() {
    let setup = prepare_cli_btc_ark_swap(
        "bark/cli_btc_build_claim_adaptor_rejects_changed_claim_public_nonce",
        "btc-ark-cli-tampered-public-nonce-relay.json",
    )
    .await;
    setup
        .ark_payer
        .run_json::<Value, _, _>([
            "swap",
            "btc-ark",
            "ark-sign-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;

    let mut relay_json: Value =
        serde_json::from_str(&tokio::fs::read_to_string(&setup.relay).await.unwrap()).unwrap();
    relay_json["claim_request"]["btc_payer_public_nonce_hex"] = "00".repeat(66).into();
    tokio::fs::write(
        &setup.relay,
        serde_json::to_vec_pretty(&relay_json).unwrap(),
    )
    .await
    .unwrap();

    let err = setup
        .btc_payer
        .try_run([
            "swap",
            "btc-ark",
            "btc-build-claim-adaptor",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await
        .expect_err("changed BTC claim public nonce must be rejected");
    assert!(
        err.to_string()
            .contains("BTC claim public nonce changed after nonce generation"),
        "{err:#}",
    );
}

#[tokio::test]
async fn cli_btc_build_claim_adaptor_rejects_changed_ark_transfer_after_funding() {
    let setup = prepare_cli_btc_ark_swap(
        "bark/cli_btc_build_claim_adaptor_rejects_changed_ark_transfer_after_funding",
        "btc-ark-cli-tampered-ark-transfer-relay.json",
    )
    .await;
    setup
        .ark_payer
        .run_json::<Value, _, _>([
            "swap",
            "btc-ark",
            "ark-sign-btc-claim",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await;

    let mut relay_json: Value =
        serde_json::from_str(&tokio::fs::read_to_string(&setup.relay).await.unwrap()).unwrap();
    let transfer_package_hex = relay_json["ark_transfer"]["transfer_package_hex"]
        .as_str()
        .unwrap();
    relay_json["ark_transfer"]["transfer_package_hex"] =
        tamper_hex_first_nibble(transfer_package_hex).into();
    tokio::fs::write(
        &setup.relay,
        serde_json::to_vec_pretty(&relay_json).unwrap(),
    )
    .await
    .unwrap();

    let err = setup
        .btc_payer
        .try_run([
            "swap",
            "btc-ark",
            "btc-build-claim-adaptor",
            "--coordinator",
            &setup.coordinator,
            "--swap",
            &setup.swap_id,
        ])
        .await
        .expect_err("changed Ark transfer must be rejected after BTC funding");
    let err_text = err.to_string();
    assert!(
        err_text.contains("invalid Ark transfer package")
            || err_text.contains("Ark transfer package is not safe to accept")
            || err_text.contains("Ark transfer does not match offered terms"),
        "{err:#}",
    );
}

fn tamper_hex_first_nibble(hex: &str) -> String {
    let mut tampered = hex.to_owned();
    let replacement = if tampered.starts_with('0') { "1" } else { "0" };
    tampered.replace_range(0..1, replacement);
    tampered
}
