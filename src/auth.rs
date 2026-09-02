//! Relay authentication policy (v4).
//!
//! A relay operator can require a **password**, a **TOTP (2FA) code**, or both before
//! a device may register. The default is no policy at all (Pulsar's public relay and a
//! plain `pulsar-relay` stay open, exactly as before v4).
//!
//! ## Why challenge–response
//!
//! The client↔relay control channel is plaintext UDP (there is no TLS to the relay), so
//! the raw password must never travel on it. Instead the relay hands the client a
//! per-attempt `nonce` in [`pulsar_proto::RelayMsg::AuthRequired`]; the client returns
//! `SHA-256(nonce || password)` in the [`pulsar_proto::AuthProof`]. A passive observer
//! learns neither the password (pre-image resistance) nor a proof reusable under a fresh
//! nonce. The nonce is **stateless**: `SHA-256(server_secret || ip || window)` truncated
//! to 16 bytes, where `window = unix_time / NONCE_STEP`. The relay accepts the current
//! and previous window, so a proof is usable for at most ~2·`NONCE_STEP` — no per-client
//! state to track or garbage-collect on the single-task event loop.
//!
//! Replaying a captured Register within that window only re-registers the SAME pubkey
//! (which is public anyway) and yields an id+token that is useless without the device's
//! X25519 private key — sessions are end-to-end encrypted. Auth gates *registration*, not
//! session content; the TOTP factor adds a rotating secret on top.

use sha2::{Digest, Sha256};

/// Seconds a challenge nonce stays valid (one window). The relay accepts the current and
/// previous window, so a client has up to ~2× this to answer a challenge.
const NONCE_STEP: u64 = 30;

/// TOTP time step (RFC 6238 default).
const TOTP_STEP: u64 = 30;

/// TOTP digit count (RFC 6238 default / what authenticator apps emit).
const TOTP_DIGITS: u32 = 6;

/// The relay's authentication policy. All-empty = open relay (the default).
#[derive(Clone, Default)]
pub struct RelayAuth {
	/// Required password (compared via a nonce-bound SHA-256 proof), or `None`.
	pub password: Option<String>,
	/// Base32-decoded TOTP shared secret, or `None`.
	pub totp_secret: Option<Vec<u8>>,
	/// Advertise (and, on the Connect path, require) end-to-end encryption.
	pub require_e2e: bool,
}

impl RelayAuth {
	/// True when at least one credential factor is required. `require_e2e` alone is NOT
	/// authentication (E2E is a peer property the relay merely advertises/insists on), so
	/// it does not make a relay challenge on registration.
	pub fn needs_credential(&self) -> bool {
		self.password.is_some() || self.totp_secret.is_some()
	}
}

/// The verdict of checking a registration's auth against the policy.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthCheck {
	/// No policy, or the supplied proof satisfied it → allow registration.
	Ok,
	/// The client sent no proof (or one bound to a stale/forged nonce) → send a fresh
	/// challenge. Carries the factors required so the client knows what to prompt for.
	Challenge { password: bool, totp: bool },
	/// A proof was sent but a factor was wrong → reject with `BadAuth`.
	Bad,
}

/// Deterministic per-attempt challenge nonce, stateless: bound to the source IP and a
/// coarse time window so the relay can validate an echoed nonce without storing it.
pub fn challenge_nonce(server_secret: &[u8; 32], ip: std::net::IpAddr, unix_time: u64) -> [u8; 16] {
	nonce_for_window(server_secret, ip, unix_time / NONCE_STEP)
}

fn nonce_for_window(server_secret: &[u8; 32], ip: std::net::IpAddr, window: u64) -> [u8; 16] {
	let mut h = Sha256::new();
	h.update(server_secret);
	match ip {
		std::net::IpAddr::V4(a) => h.update(a.octets()),
		std::net::IpAddr::V6(a) => h.update(a.octets()),
	}
	h.update(window.to_be_bytes());
	let digest = h.finalize();
	let mut out = [0u8; 16];
	out.copy_from_slice(&digest[..16]);
	out
}

/// Is `nonce` one this relay issued to `ip` within the accepted window (current or
/// previous)? Constant-time compared so timing can't reveal how close a forged nonce was.
fn nonce_is_fresh(server_secret: &[u8; 32], ip: std::net::IpAddr, unix_time: u64, nonce: &[u8; 16]) -> bool {
	let window = unix_time / NONCE_STEP;
	let cur = nonce_for_window(server_secret, ip, window);
	// `window - 1` only when window > 0 (relay uptime is always well past the epoch, but
	// guard the subtraction anyway so a clock at 0 can't underflow).
	let prev = if window > 0 {
		nonce_for_window(server_secret, ip, window - 1)
	} else {
		cur
	};
	ct_eq(nonce, &cur) || ct_eq(nonce, &prev)
}

/// Check a registration's `auth` proof against the policy.
pub fn check(
	auth: &RelayAuth,
	proof: Option<&pulsar_proto::AuthProof>,
	server_secret: &[u8; 32],
	ip: std::net::IpAddr,
	unix_time: u64,
) -> AuthCheck {
	if !auth.needs_credential() {
		return AuthCheck::Ok;
	}
	let need_pw = auth.password.is_some();
	let need_totp = auth.totp_secret.is_some();
	let Some(proof) = proof else {
		return AuthCheck::Challenge { password: need_pw, totp: need_totp };
	};
	// A proof bound to a nonce we didn't issue (or that has expired) is re-challenged with
	// a fresh nonce rather than rejected outright — the usual cause is an expired window,
	// not a wrong credential.
	if !nonce_is_fresh(server_secret, ip, unix_time, &proof.nonce) {
		return AuthCheck::Challenge { password: need_pw, totp: need_totp };
	}
	if let Some(pw) = &auth.password {
		let expected = pulsar_proto::password_proof(&proof.nonce, pw);
		match proof.password {
			Some(got) if ct_eq_bytes(&got, &expected) => {}
			_ => return AuthCheck::Bad,
		}
	}
	if let Some(secret) = &auth.totp_secret {
		match proof.totp.as_deref() {
			Some(code) if totp_valid(secret, code, unix_time) => {}
			_ => return AuthCheck::Bad,
		}
	}
	AuthCheck::Ok
}

/// Verify a TOTP `code` against `secret` at `unix_time`, accepting the current step and
/// its immediate neighbours (±1 step) to tolerate clock skew.
pub fn totp_valid(secret: &[u8], code: &str, unix_time: u64) -> bool {
	let code = code.trim();
	if code.is_empty() {
		return false;
	}
	let counter = unix_time / TOTP_STEP;
	// Guard the -1 so an early clock can't underflow.
	let lo = counter.saturating_sub(1);
	for c in lo..=counter + 1 {
		let expected = hotp(secret, c, TOTP_DIGITS);
		// Constant-time string compare of equal-length codes.
		if code.len() == expected.len() && ct_eq_bytes(code.as_bytes(), expected.as_bytes()) {
			return true;
		}
	}
	false
}

/// RFC 4226 HOTP with HMAC-SHA1, returning a zero-padded `digits`-length decimal string.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
	use hmac::{Hmac, Mac};
	use sha1::Sha1;
	type HmacSha1 = Hmac<Sha1>;
	let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
	mac.update(&counter.to_be_bytes());
	let hs = mac.finalize().into_bytes();
	let offset = (hs[hs.len() - 1] & 0x0f) as usize;
	let bin = ((hs[offset] as u32 & 0x7f) << 24)
		| ((hs[offset + 1] as u32) << 16)
		| ((hs[offset + 2] as u32) << 8)
		| (hs[offset + 3] as u32);
	let otp = bin % 10u32.pow(digits);
	format!("{otp:0width$}", width = digits as usize)
}

/// Decode a base32 (RFC 4648, upper/lowercase, optional `=` padding and spaces) TOTP
/// secret as pasted from an authenticator setup. Returns `None` on any invalid character.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
	const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let mut out = Vec::new();
	let mut buffer: u32 = 0;
	let mut bits: u32 = 0;
	for ch in s.chars() {
		if ch == '=' || ch == ' ' || ch == '-' {
			continue;
		}
		let up = ch.to_ascii_uppercase() as u8;
		let val = ALPHABET.iter().position(|&c| c == up)? as u32;
		buffer = (buffer << 5) | val;
		bits += 5;
		if bits >= 8 {
			bits -= 8;
			out.push((buffer >> bits) as u8);
		}
	}
	Some(out)
}

/// Constant-time equality for two 16-byte challenge/proof values.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
	ct_eq_bytes(a, b)
}

/// Constant-time equality for two equal-length byte slices. Examines every byte so the
/// time taken doesn't leak the position of the first mismatch. Different lengths → false.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let mut diff = 0u8;
	for (x, y) in a.iter().zip(b.iter()) {
		diff |= x ^ y;
	}
	diff == 0
}

#[cfg(test)]
mod tests {
	use super::*;
	use pulsar_proto::AuthProof;
	use std::net::IpAddr;

	fn ip() -> IpAddr {
		"203.0.113.7".parse().unwrap()
	}

	#[test]
	fn open_relay_allows_without_proof() {
		let auth = RelayAuth::default();
		assert_eq!(check(&auth, None, &[0u8; 32], ip(), 1000), AuthCheck::Ok);
		assert!(!auth.needs_credential());
	}

	#[test]
	fn password_challenge_then_success() {
		let secret = [9u8; 32];
		let auth = RelayAuth { password: Some("hunter2".into()), ..Default::default() };
		let t = 1_700_000_000;
		// No proof → challenge for password only.
		assert_eq!(
			check(&auth, None, &secret, ip(), t),
			AuthCheck::Challenge { password: true, totp: false }
		);
		// Build the proof the client would send from the issued nonce.
		let nonce = challenge_nonce(&secret, ip(), t);
		let good = AuthProof { nonce, password: Some(pulsar_proto::password_proof(&nonce, "hunter2")), totp: None };
		assert_eq!(check(&auth, Some(&good), &secret, ip(), t), AuthCheck::Ok);
		// Wrong password → Bad.
		let bad = AuthProof { nonce, password: Some(pulsar_proto::password_proof(&nonce, "wrong")), totp: None };
		assert_eq!(check(&auth, Some(&bad), &secret, ip(), t), AuthCheck::Bad);
	}

	#[test]
	fn stale_nonce_is_rechallenged_not_rejected() {
		let secret = [1u8; 32];
		let auth = RelayAuth { password: Some("pw".into()), ..Default::default() };
		let t = 1_700_000_000;
		let old_nonce = challenge_nonce(&secret, ip(), t - 10 * NONCE_STEP); // far in the past
		let proof = AuthProof { nonce: old_nonce, password: Some(pulsar_proto::password_proof(&old_nonce, "pw")), totp: None };
		assert_eq!(
			check(&auth, Some(&proof), &secret, ip(), t),
			AuthCheck::Challenge { password: true, totp: false }
		);
	}

	#[test]
	fn nonce_accepts_previous_window() {
		let secret = [2u8; 32];
		let t = 1_700_000_015; // mid-window
		let n_prev = challenge_nonce(&secret, ip(), t - NONCE_STEP);
		assert!(nonce_is_fresh(&secret, ip(), t, &n_prev));
		let n_old = challenge_nonce(&secret, ip(), t - 3 * NONCE_STEP);
		assert!(!nonce_is_fresh(&secret, ip(), t, &n_old));
	}

	#[test]
	fn totp_matches_reference_vector() {
		// RFC 6238 test vector (SHA-1, secret "12345678901234567890", T=59 → 94287082,
		// but that's 8 digits). For 6 digits at T=59, counter=1: standard value 287082.
		let secret = b"12345678901234567890";
		assert!(totp_valid(secret, "287082", 59));
		assert!(!totp_valid(secret, "000000", 59));
		// Neighbouring step tolerated.
		assert!(totp_valid(secret, &hotp(secret, 59 / TOTP_STEP + 1, 6), 59));
	}

	#[test]
	fn base32_round_trip_known() {
		// "Hello!\xDE\xAD\xBE\xEF" is arbitrary; test a known RFC 4648 vector instead:
		// base32("foobar") = MZXW6YTBOI.
		assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
		assert_eq!(base32_decode("mz xw6y tb oi").unwrap(), b"foobar"); // spaces + lowercase
		assert!(base32_decode("0189").is_none()); // 0/1/8/9 aren't in the alphabet
	}

	#[test]
	fn totp_and_password_both_required_is_mfa() {
		let secret = [3u8; 32];
		let totp_secret = base32_decode("MZXW6YTBOI").unwrap();
		let auth = RelayAuth {
			password: Some("pw".into()),
			totp_secret: Some(totp_secret.clone()),
			require_e2e: false,
		};
		let t = 1_700_000_000;
		assert_eq!(
			check(&auth, None, &secret, ip(), t),
			AuthCheck::Challenge { password: true, totp: true }
		);
		let nonce = challenge_nonce(&secret, ip(), t);
		// Right password, missing TOTP → Bad.
		let no_totp = AuthProof { nonce, password: Some(pulsar_proto::password_proof(&nonce, "pw")), totp: None };
		assert_eq!(check(&auth, Some(&no_totp), &secret, ip(), t), AuthCheck::Bad);
		// Right password + right TOTP → Ok.
		let code = hotp(&totp_secret, t / TOTP_STEP, 6);
		let both = AuthProof { nonce, password: Some(pulsar_proto::password_proof(&nonce, "pw")), totp: Some(code) };
		assert_eq!(check(&auth, Some(&both), &secret, ip(), t), AuthCheck::Ok);
	}
}
