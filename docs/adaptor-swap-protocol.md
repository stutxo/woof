# Bark BTC-Ark Swap Protocol

This document specifies the BTC-for-Ark VTXO swap implemented by
`bark swap btc-ark`.

The protocol lets Bob pay BTC on-chain and receive an Ark VTXO from Alice. Alice
receives BTC only by revealing the adaptor secret Bob needs to complete the Ark
receive. If either party stops before that reveal, the other party has an
on-chain recovery path.

This is a client-only protocol. The Ark server is not modified and is not told
that a swap is happening. It sees ordinary Ark wallet operations: an
adaptor-locked arkoor package, transaction-chain registration, and possible
emergency exits.

## TLDR Flow

1. Alice chooses adaptor secret `t` and publishes only `T = t*G`.
2. Bob funds the BTC lock.
3. Alice creates an Ark transfer with public nonces already adapted to `T`; the
   Ark server co-signs those nonces.
4. Bob accepts the adaptor-locked Ark package and gives Alice a BTC claim
   adaptor signature locked to `T`.
5. Alice claims BTC with `t`; Bob recovers `t` from that BTC signature and uses
   it to finalize the Ark receive.

## Security Summary

Under the assumptions below, neither party can steal the other party's principal:

- Alice cannot take Bob's BTC without revealing the adaptor secret `t`.
- Bob cannot complete the Ark receive without learning `t`.
- If Alice never reveals `t`, Bob refunds the BTC lock after its CSV delay.
- If Bob stalls before `t` is revealed, Alice can abort by starting emergency
  exits for the original Ark input VTXOs.
- If Alice reveals `t` and then tries an old-state Ark exit, Bob has the Ark
  `vtxo_exit_delta` response window to complete, register, and import the Ark
  transfer.

This is not grief-free. Either party can force the other into delay, monitoring,
and on-chain fees. The atomicity property is "no counterparty rug with correct
monitoring and fallback execution", not "instant off-chain rollback".

## Roles

- Alice: `ark_payer`. Pays an Ark VTXO and receives BTC on-chain.
- Bob: `btc_payer`. Funds a BTC Taproot lock and receives an Ark VTXO.

## Notation

- `t`: Alice's adaptor secret.
- `T = t*G`: Alice's public adaptor point.
- `A_btc`: Alice's BTC claim public key.
- `B_btc`: Bob's BTC claim public key.
- `K = MuSig2(A_btc, B_btc)`: aggregate BTC claim public key.
- `refund_key`: Bob's BTC refund key.
- `refund_delay`: CSV delay on Bob's BTC refund path.
- `exit_delta`: Ark VTXO unilateral-exit delay.
- `ark_inputs`: Alice's original Ark input VTXOs selected for the transfer.
- `ark_transfer`: adaptor-locked arkoor transfer package.

## BTC Lock

Bob funds a Taproot output with:

- Key path: cooperative MuSig2 spend by `K = MuSig2(A_btc, B_btc)`.
- Script path: Bob's `refund_key` after `refund_delay`.

Alice has no unilateral BTC spend. Bob has no key-path spend without Alice's
MuSig2 participation.

The cooperative BTC claim transaction pays Alice's requested BTC payout script.
Bob creates a MuSig2 adaptor signature for that exact transaction, locked to
Alice's adaptor point `T`. Alice can finalize the BTC claim only with `t`, and
the final Schnorr signature lets Bob recover `t`.

## Ark Transfer

Alice creates an adaptor-locked arkoor package that pays Bob's Ark receive
policy. The package contains server partial signatures and Alice adaptor
pre-signatures, but not final signatures. Bob can only finalize the received
VTXO package with `t`.

The Ark transfer sets up the adaptor lock before server co-signing. For each
arkoor/checkpoint signature, Alice publishes a user public nonce whose first
nonce point is offset by `T` and keeps the corresponding secret nonce local. The
Ark server co-signs against those already-adapted public nonces. Alice then
combines the server partial signatures with her secret nonces into adaptor
pre-signatures. Those pre-signatures are safe to send to Bob because they verify
only as adaptor pre-signatures against `T`; they do not become valid Ark
transaction signatures until Bob learns `t`.

When Alice prepares the transfer, her client stores:

- The commitment hash of the accepted `ark_transfer`.
- The original Ark input VTXO IDs.
- Her adaptor secret `t`.

Her client also locks the original inputs locally so they are not accidentally
selected for another spend while the swap is pending.

## Relay Artifacts

The current POC uses a JSON relay file. The relay file is public coordination
data and must never contain mnemonics, secret nonces, or adaptor secrets.

- `request`: Bob's amount, Ark receive address, BTC claim public key, BTC
  refund key, fee rate, and refund delay.
- `terms`: Alice's BTC payout script, BTC claim public key, and adaptor point
  `T`.
- `btc_funding`: Bob's BTC lock funding transaction data.
- `claim_request`: unsigned BTC claim transaction, sighash, tap tweak, and Bob's
  BTC claim nonce.
- `ark_transfer`: adaptor-locked arkoor package plus public offer metadata.
- `ark_claim_partial`: Alice's BTC claim nonce and partial signature.
- `btc_claim_adaptor`: Bob's BTC claim adaptor signature package.
- `btc_refund`: Bob's BTC refund transaction, if the refund path is used.

The relay status is only coordination state. It is not a security boundary. Each
client must verify local pinned state and chain state.

## Happy Path

Funding preconditions:

- Bob, the BTC payer, must have enough on-chain BTC to fund the BTC lock and
  pay the funding transaction fee.
- Alice, the Ark payer, must have enough spendable Ark VTXOs to create the
  adaptor-locked Ark transfer.

### 1. Bob Creates A Request

Bob chooses:

- Swap amount.
- Ark receive address.
- BTC claim public key `B_btc`.
- BTC refund key.
- BTC fee rate.
- BTC refund delay.

Bob writes `request` and local `BtcPayer` state.

Command:

```sh
bark swap btc-ark btc-request \
  --coordinator "$RELAY" \
  --amount "$AMOUNT" \
  --ark-receive "$BOB_ARK_RECEIVE" \
  --fee-rate "$FEE_RATE" \
  --refund-delay "$REFUND_DELAY"
```

### 2. Alice Publishes Terms

Alice verifies Bob's Ark receive address. She chooses:

- BTC payout address.
- BTC claim public key `A_btc`.
- Adaptor secret `t`, publishing only `T`.

Alice writes `terms` and local `ArkPayer` state.

Command:

```sh
bark swap btc-ark ark-offer \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID" \
  --btc-payout "$ALICE_BTC_PAYOUT"
```

### 3. Bob Funds The BTC Lock

Bob verifies Alice's terms, constructs the Taproot lock, broadcasts the funding
transaction, and constructs the exact cooperative BTC claim transaction.

Bob stores the BTC claim nonce locally and writes `btc_funding` plus
`claim_request`.

Command:

```sh
bark swap btc-ark btc-fund \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

### 4. Alice Creates The Adaptor-Locked Ark Transfer

Alice waits for the BTC lock to confirm. She verifies:

- The BTC lock pays the expected Taproot contract.
- The claim transaction pays her expected BTC payout script.
- The claim sighash matches the expected transaction and Taproot tweak.

Alice then creates an adaptor-locked arkoor transfer to Bob's Ark receive policy
using adaptor point `T`. This is the first Ark-side step that consumes the
original inputs from the server's perspective. Bob still cannot import the
outputs because the package is only adaptor-signed.

Alice stores the accepted transfer hash and original input IDs locally, locks
the inputs locally, and writes `ark_transfer`.

Command:

```sh
bark swap btc-ark ark-transfer \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

### 5. Alice Signs Her BTC Claim Partial

Alice signs a MuSig2 partial signature for the exact BTC claim transaction and
Bob's published BTC claim nonce. This does not reveal `t`.

Command:

```sh
bark swap btc-ark ark-sign-btc-claim \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

### 6. Bob Builds The BTC Claim Adaptor Signature

Bob verifies the Ark transfer before accepting it:

- The transfer package matches the offered amount and BTC payout script.
- The transfer pays Bob's Ark receive policy.
- The server pubkey and adaptor point match the terms.
- The output VTXOs expire after the BTC refund window.
- The transfer package hash matches Bob's locally pinned state once accepted.

Bob then combines Alice's BTC claim partial with his secret nonce into a BTC
claim adaptor signature package bound to `T`. After building the adaptor
package, Bob no longer needs the secret nonce for refund safety.

Command:

```sh
bark swap btc-ark btc-build-claim-adaptor \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

### 7. Alice Claims BTC And Reveals `t`

Alice verifies Bob's adaptor package:

- The adaptor pre-signature verifies against `T`.
- The sighash matches the pinned BTC claim transaction.
- The aggregate key matches the Taproot BTC lock key.

Alice finalizes the BTC claim signature with `t` and broadcasts the BTC claim.
The published final Schnorr signature reveals `t` to Bob.

Command:

```sh
bark swap btc-ark ark-finalize-btc-claim \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

### 8. Bob Completes The Ark Receive

Bob watches for the BTC claim transaction. Once it is visible, Bob recovers `t`
from the final BTC signature and his adaptor package. Bob finalizes the
adaptor-locked Ark transfer, registers the signed transaction chain with the Ark
server, and imports the received Ark VTXO.

Command:

```sh
bark swap btc-ark btc-complete-ark \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Bob should run this promptly after Alice's BTC claim becomes visible. If Alice
maliciously attempts to exit old Ark state after revealing `t`, Bob's practical
response window is until Alice's old exit confirms plus the Ark `exit_delta`.
For example, with `vtxo_exit_delta = 144`, Bob has roughly 144 blocks after that
old exit confirms. This window is a fallback margin, not the intended response
time.

Check the server's value:

```sh
bark ark-info | jq '.vtxo_exit_delta'
```

## Abort Paths

### Bob Stops Before Funding

No funds are locked. Either party can discard the relay.

### Alice Stops After Offer

No Ark funds are spent. Bob should not fund until he has verified terms. Either
party can discard the relay.

### Alice Stops After BTC Funding, Before Ark Transfer

Bob waits until the BTC lock refund path matures and refunds:

```sh
bark swap btc-ark btc-refund \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Alice has not created the Ark transfer, so Alice has no Ark-side loss.

### Bob Stops After Ark Transfer, Before BTC Claim Is Visible

Bob cannot complete the Ark receive because `t` has not been revealed. Alice can
abort by starting emergency exits for the original Ark input VTXOs:

```sh
bark swap btc-ark ark-abort \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

Alice then progresses her normal emergency exit:

```sh
bark exit progress
```

Bob recovers his BTC after the BTC refund delay:

```sh
bark swap btc-ark btc-refund \
  --coordinator "$RELAY" \
  --swap "$SWAP_ID"
```

### Alice Tries To Abort After BTC Claim Is Visible

This is not a valid abort. The BTC claim signature may reveal `t`, so Bob should
complete the Ark receive regardless of relay status. The client checks chain
visibility and refuses `ark-abort` once the BTC claim is visible.

Bob's `btc-complete-ark` path should not trust a `Cancelled` relay status over
chain evidence. If the BTC claim is visible and the adaptor package is valid,
Bob should recover `t`, register the Ark transfer chain, and import the VTXO.

### Alice Reveals `t` Then Publishes An Old Ark Exit

This is the main old-state attack to review.

Once Bob has completed and registered the finalized Ark transfer, Alice's old
exit should not steal Bob's funds. The server/watchman knows the original Ark
VTXO was spent out-of-round and can progress the registered spend/checkpoint
path. Alice can still cause delay and on-chain work.

Bob's operational requirement is to complete/register/import before the old exit
becomes claimable:

```text
old exit confirmation height + vtxo_exit_delta
```

## Invariants

The protocol relies on these invariants:

- Bob funds only after verifying Alice's public terms.
- Alice creates `ark_transfer` only after the BTC lock is confirmed, unless
  using `--allow-unconfirmed` in local tests.
- Alice reveals `t` only by broadcasting the BTC claim.
- Bob accepts only one pinned `ark_transfer` commitment hash.
- Alice's abort uses the original Ark input IDs pinned in local state.
- Bob completes the Ark receive from chain-visible BTC claim data, not from
  relay status alone.
- Bob's BTC refund path remains available even after he has built the BTC claim
  adaptor package.
