use std::fmt;
use std::io::Write as _;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{
	Message, Parity, PublicKey, Scalar, SecretKey, XOnlyPublicKey, schnorr,
};

use super::{PublicNonce, SecretNonce, nonce_pair_with_msg, pubkey_to, secpm};

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum AdaptorError {
	#[error("invalid adaptor nonce tweak")]
	InvalidNonceTweak,
	#[error("invalid adaptor signature scalar")]
	InvalidSignatureScalar,
	#[error("invalid BIP340 challenge scalar")]
	InvalidChallengeScalar,
	#[error("adapted signature does not verify")]
	InvalidAdaptedSignature,
	#[error("final signature does not reveal the expected adaptor secret")]
	UnexpectedAdaptorSecret,
}

/// Secret scalar that completes an adaptor pre-signature.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct AdaptorSecret(SecretKey);

impl fmt::Debug for AdaptorSecret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[adaptor secret redacted]")
	}
}

impl AdaptorSecret {
	pub fn new(secret: SecretKey) -> Self {
		Self(secret)
	}

	pub fn secret_key(&self) -> SecretKey {
		self.0
	}

	pub fn point(&self) -> PublicKey {
		PublicKey::from_secret_key(&crate::SECP, &self.0)
	}

	fn negate(self) -> Self {
		Self(self.0.negate())
	}
}

/// Schnorr-shaped pre-signature that is not valid until finalized with the adaptor secret.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdaptorPreSignature(schnorr::Signature);

impl AdaptorPreSignature {
	pub fn new(sig: schnorr::Signature) -> Self {
		Self(sig)
	}

	pub fn as_pre_signature(&self) -> schnorr::Signature {
		self.0
	}

	pub fn finalize_with_secret(
		&self,
		secret: AdaptorSecret,
		aggregate_key: XOnlyPublicKey,
		msg: [u8; 32],
	) -> Result<schnorr::Signature, AdaptorError> {
		let add = tweak_signature_scalar(self.0, secret)?;
		if verify_schnorr(add, aggregate_key, msg) {
			return Ok(add);
		}

		let sub = tweak_signature_scalar(self.0, secret.negate())?;
		if verify_schnorr(sub, aggregate_key, msg) {
			return Ok(sub);
		}

		Err(AdaptorError::InvalidAdaptedSignature)
	}

	pub fn recover_secret(
		&self,
		final_sig: schnorr::Signature,
		adaptor_point: PublicKey,
	) -> Result<AdaptorSecret, AdaptorError> {
		let delta = subtract_signature_scalars(final_sig, self.0)?;
		let delta_secret = AdaptorSecret::new(delta);
		let delta_point = delta_secret.point();

		if delta_point == adaptor_point {
			Ok(delta_secret)
		} else if delta_point == adaptor_point.negate(&crate::SECP) {
			Ok(delta_secret.negate())
		} else {
			Err(AdaptorError::UnexpectedAdaptorSecret)
		}
	}

	pub fn verify_adaptor(
		&self,
		adaptor_point: PublicKey,
		aggregate_key: XOnlyPublicKey,
		msg: [u8; 32],
	) -> Result<(), AdaptorError> {
		let sig = self.as_pre_signature();
		let sig_bytes = sig.serialize();

		let r_x = XOnlyPublicKey::from_slice(&sig_bytes[..32])
			.map_err(|_| AdaptorError::InvalidAdaptedSignature)?;
		let r = PublicKey::from_x_only_public_key(r_x, Parity::Even);

		let s = signature_scalar(sig)?;
		let s_g = PublicKey::from_secret_key(&crate::SECP, &s);

		let aggregate_pubkey = PublicKey::from_x_only_public_key(aggregate_key, Parity::Even);
		let challenge = bip340_challenge_scalar(
			sig_bytes[..32].try_into().expect("signature R is 32 bytes"),
			&aggregate_key.serialize(),
			msg,
		)?;
		let challenge_pubkey = aggregate_pubkey
			.mul_tweak(&crate::SECP, &challenge)
			.map_err(|_| AdaptorError::InvalidAdaptedSignature)?;
		let expected = r.combine(&challenge_pubkey)
			.map_err(|_| AdaptorError::InvalidAdaptedSignature)?;

		let add_adaptor = s_g.combine(&adaptor_point)
			.map_err(|_| AdaptorError::InvalidAdaptedSignature)?;
		if add_adaptor == expected {
			return Ok(());
		}

		let sub_adaptor = s_g.combine(&adaptor_point.negate(&crate::SECP))
			.map_err(|_| AdaptorError::InvalidAdaptedSignature)?;
		if sub_adaptor == expected {
			return Ok(());
		}

		Err(AdaptorError::InvalidAdaptedSignature)
	}
}

impl crate::ProtocolEncoding for AdaptorPreSignature {
	fn encode<W: std::io::Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
		crate::ProtocolEncoding::encode(&self.0, w)
	}

	fn decode<R: std::io::Read + ?Sized>(
		r: &mut R,
	) -> Result<Self, crate::encode::ProtocolDecodingError> {
		Ok(Self(crate::ProtocolEncoding::decode(r)?))
	}
}

pub fn adaptor_nonce_pair_with_msg(
	key: &bitcoin::secp256k1::Keypair,
	msg: &[u8; 32],
	adaptor_point: PublicKey,
) -> Result<(SecretNonce, PublicNonce), AdaptorError> {
	let (secret_nonce, public_nonce) = nonce_pair_with_msg(key, msg);
	let public_nonce = tweak_public_nonce(public_nonce, adaptor_point)?;
	Ok((secret_nonce, public_nonce))
}

fn tweak_public_nonce(
	public_nonce: PublicNonce,
	adaptor_point: PublicKey,
) -> Result<PublicNonce, AdaptorError> {
	let mut bytes = public_nonce.serialize();

	// A MuSig public nonce serializes as two compressed points. Offsetting the
	// first point offsets the final aggregate nonce independently of the nonce
	// coefficient applied to the second point.
	let first = secpm::PublicKey::from_slice(&bytes[..33])
		.map_err(|_| AdaptorError::InvalidNonceTweak)?;
	let tweaked = first.combine(&pubkey_to(adaptor_point))
		.map_err(|_| AdaptorError::InvalidNonceTweak)?;
	bytes[..33].copy_from_slice(&tweaked.serialize());

	PublicNonce::from_byte_array(&bytes)
		.map_err(|_| AdaptorError::InvalidNonceTweak)
}

fn signature_scalar(sig: schnorr::Signature) -> Result<SecretKey, AdaptorError> {
	let bytes = sig.serialize();
	SecretKey::from_slice(&bytes[32..])
		.map_err(|_| AdaptorError::InvalidSignatureScalar)
}

fn signature_with_scalar(
	sig: schnorr::Signature,
	scalar: SecretKey,
) -> Result<schnorr::Signature, AdaptorError> {
	let mut bytes = sig.serialize();
	bytes[32..].copy_from_slice(&scalar.secret_bytes());
	schnorr::Signature::from_slice(&bytes)
		.map_err(|_| AdaptorError::InvalidSignatureScalar)
}

fn tweak_signature_scalar(
	sig: schnorr::Signature,
	secret: AdaptorSecret,
) -> Result<schnorr::Signature, AdaptorError> {
	let scalar = signature_scalar(sig)?;
	let tweaked = scalar.add_tweak(&Scalar::from(secret.secret_key()))
		.map_err(|_| AdaptorError::InvalidSignatureScalar)?;
	signature_with_scalar(sig, tweaked)
}

fn subtract_signature_scalars(
	final_sig: schnorr::Signature,
	pre_sig: schnorr::Signature,
) -> Result<SecretKey, AdaptorError> {
	let final_scalar = signature_scalar(final_sig)?;
	let pre_scalar = signature_scalar(pre_sig)?;
	final_scalar.add_tweak(&Scalar::from(pre_scalar.negate()))
		.map_err(|_| AdaptorError::InvalidSignatureScalar)
}

fn bip340_challenge_scalar(
	r_x: &[u8; 32],
	aggregate_key_x: &[u8; 32],
	msg: [u8; 32],
) -> Result<Scalar, AdaptorError> {
	let tag = sha256::Hash::hash(b"BIP0340/challenge").to_byte_array();
	let mut engine = sha256::Hash::engine();
	engine.write_all(&tag).expect("sha256 write cannot fail");
	engine.write_all(&tag).expect("sha256 write cannot fail");
	engine.write_all(r_x).expect("sha256 write cannot fail");
	engine.write_all(aggregate_key_x).expect("sha256 write cannot fail");
	engine.write_all(&msg).expect("sha256 write cannot fail");

	let challenge = sha256::Hash::from_engine(engine).to_byte_array();
	Scalar::from_be_bytes(challenge).map_err(|_| AdaptorError::InvalidChallengeScalar)
}

fn verify_schnorr(sig: schnorr::Signature, aggregate_key: XOnlyPublicKey, msg: [u8; 32]) -> bool {
	let msg = Message::from_digest(msg);
	crate::SECP.verify_schnorr(&sig, &msg, &aggregate_key).is_ok()
}

#[cfg(test)]
mod test {
	use bitcoin::secp256k1::{Keypair, SecretKey, rand};

	use super::*;
	use crate::musig::{
		deterministic_partial_sign, nonce_agg, partial_sign, tweaked_key_agg,
	};

	#[test]
	fn hidden_adaptor_nonce_finalizes_and_recovers_secret() {
		let user_keypair = Keypair::new(&crate::SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&crate::SECP, &mut rand::thread_rng());
		let adaptor_secret = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng()));
		let adaptor_point = adaptor_secret.point();
		let msg = [42u8; 32];
		let tweak = [7u8; 32];

		let (user_sec_nonce, user_pub_nonce) =
			adaptor_nonce_pair_with_msg(&user_keypair, &msg, adaptor_point)
				.expect("adaptor nonce must be valid");

		let (server_pub_nonce, server_partial_sig) = deterministic_partial_sign(
			&server_keypair,
			[user_keypair.public_key()],
			&[&user_pub_nonce],
			msg,
			Some(tweak),
		);

		let agg_nonce = nonce_agg(&[&user_pub_nonce, &server_pub_nonce]);
		let (_user_partial_sig, pre_sig) = partial_sign(
			[user_keypair.public_key(), server_keypair.public_key()],
			agg_nonce,
			&user_keypair,
			user_sec_nonce,
			msg,
			Some(tweak),
			Some(&[&server_partial_sig]),
		);
		let pre_sig = AdaptorPreSignature::new(
			pre_sig.expect("pre-signature exists when server partial is provided"),
		);

		let aggregate_key = tweaked_key_agg(
			[user_keypair.public_key(), server_keypair.public_key()],
			tweak,
		).1.x_only_public_key().0;

		assert!(!verify_schnorr(pre_sig.as_pre_signature(), aggregate_key, msg));
		pre_sig.verify_adaptor(adaptor_point, aggregate_key, msg)
			.expect("pre-signature verifies against adaptor point");

		let wrong_adaptor_point = AdaptorSecret::new(SecretKey::new(&mut rand::thread_rng())).point();
		assert!(pre_sig.verify_adaptor(wrong_adaptor_point, aggregate_key, msg).is_err());

		let final_sig = pre_sig.finalize_with_secret(adaptor_secret, aggregate_key, msg)
			.expect("adaptor secret must complete the pre-signature");

		let recovered = pre_sig.recover_secret(final_sig, adaptor_point)
			.expect("final signature must reveal the adaptor secret");
		assert_eq!(recovered.secret_key(), adaptor_secret.secret_key());
		assert!(verify_schnorr(final_sig, aggregate_key, msg));
	}
}
