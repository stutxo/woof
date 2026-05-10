# BTC-Ark Swap Walkthrough

For the protocol-level review document, see [adaptor-swap-protocol.md](adaptor-swap-protocol.md).

This is a proof-of-concept BTC-to-Ark VTXO swap using
`bark swap btc-ark`. The two participants exchange a relay JSON file manually:
copy it over chat, shared storage, or a local filesystem while testing. There is
no transport protocol in this POC.

The Ark server is not told that a swap is happening. It only sees normal wallet
operations, including a normal adaptor-locked Ark transfer package when the Ark
payer reaches that step.

## Roles And Safety

- Bob is the `btc_payer`: he funds a BTC Taproot lock and receives the Ark VTXO.
- Alice is the `ark_payer`: she pays an Ark VTXO and receives BTC on-chain.

The safety boundary is the command order:

```text
btc-request -> ark-offer -> btc-fund -> ark-transfer -> claim flow
```

`ark-offer` publishes public terms only. It does not spend or lock Ark funds.
`ark-transfer` is the first irreversible Ark step, and it happens only after the
BTC lock is visible. If the Ark payer stops after `btc-fund`, the BTC payer can
run `btc-refund` after the CSV delay. If the Ark payer already created the
adaptor-locked Ark transfer but has not revealed the adaptor secret by claiming
BTC, she can run `ark-abort` to start emergency exits for the original Ark
input VTXOs.

The BTC lock is not a normal single-party address. Bob contributes a BTC claim
public key in `btc-request`, and Alice contributes a BTC claim public key in
`ark-offer`. Both sides combine those keys into the same MuSig2 aggregate key
and use it as the Taproot internal key for the lock. This public-key aggregation
is enough to derive the address; it is not enough to spend it.

On the happy path, Alice claims the BTC with a cooperative MuSig2 signature over
the lock's Taproot output key. That spend still needs the normal MuSig2 signing
round data: Bob publishes a claim nonce for the exact BTC claim transaction,
Alice replies with her nonce and partial signature, and Bob combines them into an
adaptor signature bound to Alice's Ark adaptor secret. When Alice finalizes and
broadcasts the BTC claim, the final signature reveals the secret Bob needs to
complete the Ark receive. On the abort path, the same Taproot output has a script
path that lets Bob refund after the CSV delay; Alice has no unilateral spend.

## Abort And Recovery

This POC does not have an instant off-chain rollback. Its client-only safety
path is recovery by timeout and emergency exit:

- Before `ark-transfer`, Alice can cancel without touching Ark funds.
- After `ark-transfer`, Bob still cannot complete the Ark receive unless Alice
  reveals the adaptor secret `t`.
- Alice reveals `t` only by finalizing and broadcasting the BTC claim.
- If Bob stops before that BTC claim is visible, Alice can run `ark-abort`. This
  marks the swap cancelled locally and starts emergency exits for the original
  Ark input VTXOs recorded in her swap state.
- After Alice aborts, Bob should wait for the BTC lock's CSV delay and run
  `btc-refund`.

`ark-abort` is only safe before the BTC claim transaction is visible. Once Alice
has broadcast the BTC claim, the final Schnorr signature can reveal `t`, so Bob
may be able to complete the Ark receive.

## Setup

Build `bark`, or point `BARK` at an existing binary:

```sh
export BARK=target/debug/bark
```

For a one-wallet loopback test:

```sh
export DATADIR=/tmp/bark-swap-loopback
export RELAY=/tmp/btc-ark-relay.json
export SWAP_AMOUNT="10000 sats"
```

Create and fund a signet wallet:

```sh
$BARK --datadir "$DATADIR" create \
  --signet \
  --ark https://ark.signet.2nd.dev/ \
  --esplora https://esplora.signet.2nd.dev/

$BARK --quiet --datadir "$DATADIR" onchain address
```

Send signet coins to the address. The wallet needs enough on-chain funds to
board the Ark VTXO being swapped and still fund the BTC lock plus fees.

Board the Ark funds, then wait until they are spendable:

```sh
$BARK --datadir "$DATADIR" board "$SWAP_AMOUNT"
$BARK --datadir "$DATADIR" balance
$BARK --datadir "$DATADIR" vtxos
```

Collect the destinations:

```sh
export BTC_PAYOUT="$($BARK --quiet --datadir "$DATADIR" onchain address | jq -r '.address')"
export ARK_RECEIVE="$($BARK --quiet --datadir "$DATADIR" address)"
```

`BTC_PAYOUT` belongs to the logical `ark_payer`. `ARK_RECEIVE` belongs to the
logical `btc_payer`. In a real two-wallet test, run the relevant command from
the relevant participant's wallet and copy the relay file between steps.

## Happy Path

### 1. BTC payer creates the request

```sh
$BARK --datadir "$DATADIR" swap btc-ark btc-request \
  --coordinator "$RELAY" \
  --amount "$SWAP_AMOUNT" \
  --ark-receive "$ARK_RECEIVE" \
  --fee-rate 1 \
  --refund-delay 144
```

Expected output:

```json
{ "status": "Requested", "next": "ark-offer" }
```

Save the swap ID:

```sh
export SWAP_ID="$(jq -r '.swap_id' "$RELAY")"
```

### 2. Ark payer publishes terms

```sh
$BARK --datadir "$DATADIR" swap btc-ark ark-offer \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID" \
  --btc-payout "$BTC_PAYOUT"
```

Expected output:

```json
{ "status": "Offered", "next": "btc-fund" }
```

This writes the amount, BTC payout script, adaptor point `T`, and Ark payer BTC
claim key into the relay file.

### 3. BTC payer funds the BTC lock

```sh
$BARK --datadir "$DATADIR" swap btc-ark btc-fund \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Expected output:

```json
{ "status": "BtcFunded", "next": "ark-transfer" }
```

This broadcasts the BTC funding transaction and writes the cooperative BTC claim
template into the relay file.

### 4. Ark payer creates the Ark transfer

Wait for the BTC lock to confirm. The Ark-side commands fail if the lock is not
confirmed, unless `--allow-unconfirmed` is passed for local testing.

```sh
$BARK --datadir "$DATADIR" swap btc-ark ark-transfer \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Expected output:

```json
{ "status": "BtcFunded", "next": "ark-sign-btc-claim" }
```

This is the first step that creates the adaptor-locked Ark transfer package.
Alice's wallet also locks the original Ark input VTXOs locally so they are not
accidentally selected for another spend while the swap is pending.

### 5. Ark payer signs the BTC claim partial

```sh
$BARK --datadir "$DATADIR" swap btc-ark ark-sign-btc-claim \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Expected output:

```json
{ "next": "btc-build-claim-adaptor" }
```

### 6. BTC payer builds the BTC adaptor signature

```sh
$BARK --datadir "$DATADIR" swap btc-ark btc-build-claim-adaptor \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Expected output:

```json
{ "status": "BtcClaimReady", "next": "ark-finalize-btc-claim" }
```

### 7. Ark payer claims BTC

```sh
$BARK --datadir "$DATADIR" swap btc-ark ark-finalize-btc-claim \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Expected output includes `claim_txid` and points to `btc-complete-ark`.

### 8. BTC payer completes the Ark receive

After the BTC claim transaction is visible to the chain source:

```sh
$BARK --datadir "$DATADIR" swap btc-ark btc-complete-ark \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Expected output:

```json
{ "status": "ArkCompleted", "next": "done" }
```

## Refund Path

If the Ark payer stops after `btc-fund`, the BTC payer waits for the CSV delay
and refunds the BTC lock:

```sh
$BARK --datadir "$DATADIR" swap btc-ark btc-refund \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

`btc-refund` fails until the BTC funding transaction has more confirmations
than `--refund-delay`.

## Ark Abort Path

Alice can abort after `ark-transfer` as long as she has not run
`ark-finalize-btc-claim` and the BTC claim transaction is not visible:

```sh
$BARK --datadir "$DATADIR" swap btc-ark ark-abort \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Expected output:

```json
{
  "status": "Cancelled",
  "next": "exit-progress",
  "exit_required": true,
  "exit_next": "exit-progress"
}
```

The output includes `exited_vtxos`, the original Ark input VTXOs now tracked by
Alice's emergency exit process. Alice should keep progressing exits with the
normal wallet command:

```sh
$BARK --datadir "$DATADIR" exit progress
```

Bob cannot complete the Ark transfer because `t` was never revealed. Once the
BTC refund delay matures, Bob recovers the BTC lock:

```sh
$BARK --datadir "$DATADIR" swap btc-ark btc-refund \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

## Relay Contents

The relay file is public coordination data. It must not contain wallet mnemonics,
adaptor secrets, or secret nonces. Over the happy path it accumulates:

- `request`: BTC payer amount, Ark receive address, BTC claim/refund keys, fee
  rate, and refund delay.
- `terms`: Ark payer BTC payout, adaptor point `T`, and Ark payer BTC claim key.
- `btc_funding` and `claim_request`: BTC lock funding data and unsigned claim
  transaction template.
- `ark_transfer`: adaptor-locked Ark transfer package.
- `ark_claim_partial` and `btc_claim_adaptor`: signatures needed to let the Ark
  payer claim BTC and reveal the adaptor secret.
