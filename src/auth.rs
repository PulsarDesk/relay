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
	/// No policy, or the supplied proof satisfied it → allow registration. The caller
	/// ISSUES a fresh access key so the device never has to be prompted again.
	Ok,
	/// The device authenticated with an already-issued access key → allow registration
	/// WITHOUT minting a new key (it keeps the one it has).
	KeyOk,
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
fn nonce_is_fresh(
	server_secret: &[u8; 32],
	ip: std::net::IpAddr,
	unix_time: u64,
	nonce: &[u8; 16],
) -> bool {
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
///
/// `pubkey` is the registering device's X25519 public key — access keys are bound to it,
/// so a key that leaks is useless on any other device.
pub fn check(
	auth: &RelayAuth,
	proof: Option<&pulsar_proto::AuthProof>,
	server_secret: &[u8; 32],
	ip: std::net::IpAddr,
	unix_time: u64,
	pubkey: &[u8; 32],
) -> AuthCheck {
	if !auth.needs_credential() {
		return AuthCheck::Ok;
	}
	let need_pw = auth.password.is_some();
	let need_totp = auth.totp_secret.is_some();
	let Some(proof) = proof else {
		return AuthCheck::Challenge {
			password: need_pw,
			totp: need_totp,
		};
	};
	// A stored ACCESS KEY short-circuits the interactive factors: this device already
	// proved itself once. Checked first and, on success, returns `KeyOk` so the caller
	// knows NOT to mint another key. A key that no longer validates (the operator
	// changed the relay's credentials, or it was issued by a different relay) falls
	// through to the normal challenge instead of hard-failing, so the user simply gets
	// asked for their password/2FA again.
	if let Some(key) = proof.key.as_deref() {
		if key_is_valid(auth, key, pubkey) {
			return AuthCheck::KeyOk;
		}
		if proof.password.is_none() && proof.totp.is_none() {
			return AuthCheck::Challenge {
				password: need_pw,
				totp: need_totp,
			};
		}
	}
	// A proof bound to a nonce we didn't issue (or that has expired) is re-challenged with
	// a fresh nonce rather than rejected outright — the usual cause is an expired window,
	// not a wrong credential.
	if !nonce_is_fresh(server_secret, ip, unix_time, &proof.nonce) {
		return AuthCheck::Challenge {
			password: need_pw,
			totp: need_totp,
		};
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

/// One 2FA enrollment: everything the operator needs to add the relay to an
/// authenticator app, and the exact secret to hand back to the relay.
#[derive(Clone, Debug)]
pub struct TotpEnrollment {
	/// The shared secret, base32 (what `--auth-totp` takes).
	pub secret: String,
	/// The same secret in 4-character groups — what a human types when a QR can't be
	/// scanned ("özel kod").
	pub secret_grouped: String,
	/// `otpauth://totp/...` URI that authenticator apps consume.
	pub uri: String,
	/// The URI rendered as a scannable QR, as an inline SVG document (for app UIs).
	pub qr_svg: String,
	/// The URI rendered as a scannable QR in unicode half-blocks (for a terminal).
	pub qr_terminal: String,
}

/// Mint a fresh TOTP enrollment for a relay: a random 160-bit secret (the RFC 4226
/// recommendation, and what authenticator apps expect) plus its QR/manual-entry forms.
///
/// `label` is what shows up in the authenticator (e.g. the relay's host:port), `issuer`
/// the app name. Nothing is stored here — the caller decides whether to run the relay
/// with the returned secret.
pub fn generate_totp(label: &str, issuer: &str) -> TotpEnrollment {
	let mut raw = [0u8; 20];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
	let secret = base32_encode(&raw);
	enrollment_from_secret(&secret, label, issuer)
}

/// Build the enrollment views (URI + QRs + grouped form) for an EXISTING base32 secret,
/// so an operator who already configured one can re-display its QR without rotating it.
pub fn enrollment_from_secret(secret: &str, label: &str, issuer: &str) -> TotpEnrollment {
	let uri = otpauth_uri(secret, label, issuer);
	let (qr_svg, qr_terminal) = render_qr(&uri);
	TotpEnrollment {
		secret: secret.to_string(),
		secret_grouped: group4(secret),
		uri,
		qr_svg,
		qr_terminal,
	}
}

/// The `otpauth://totp/` URI authenticator apps scan. Parameters are spelled out
/// explicitly (SHA1 / 6 digits / 30 s) so an app never has to guess our defaults.
pub fn otpauth_uri(secret: &str, label: &str, issuer: &str) -> String {
	format!(
		"otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
		percent_encode(issuer),
		percent_encode(label),
		secret,
		percent_encode(issuer),
		TOTP_DIGITS,
		TOTP_STEP
	)
}

/// Render `data` as a QR twice: an inline SVG document and unicode half-blocks. An
/// encoding failure (only possible for absurdly long input) yields empty strings rather
/// than panicking — the caller still has the secret to type in by hand.
fn render_qr(data: &str) -> (String, String) {
	use qrcode::render::{svg, unicode};
	let Ok(code) = qrcode::QrCode::new(data.as_bytes()) else {
		return (String::new(), String::new());
	};
	let svg = code
		.render::<svg::Color>()
		.min_dimensions(240, 240)
		.quiet_zone(true)
		.dark_color(svg::Color("#000000"))
		.light_color(svg::Color("#ffffff"))
		.build();
	let term = code
		.render::<unicode::Dense1x2>()
		.quiet_zone(true)
		.dark_color(unicode::Dense1x2::Light)
		.light_color(unicode::Dense1x2::Dark)
		.build();
	(svg, term)
}

/// Split into 4-character groups for readable manual entry (`JBSW Y3DP EHPK …`).
fn group4(s: &str) -> String {
	s.chars()
		.collect::<Vec<_>>()
		.chunks(4)
		.map(|c| c.iter().collect::<String>())
		.collect::<Vec<_>>()
		.join(" ")
}

/// Minimal percent-encoding for the otpauth label/issuer (they may contain spaces or
/// `:`/`/`, which would otherwise break the URI's own structure).
fn percent_encode(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
				out.push(b as char)
			}
			_ => out.push_str(&format!("%{b:02X}")),
		}
	}
	out
}

/// Encode bytes as base32 (RFC 4648, uppercase, unpadded) — the form authenticator apps
/// and `--auth-totp` accept. Inverse of [`base32_decode`].
pub fn base32_encode(bytes: &[u8]) -> String {
	const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let mut out = String::new();
	let mut buffer: u32 = 0;
	let mut bits: u32 = 0;
	for &b in bytes {
		buffer = (buffer << 8) | b as u32;
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
		}
	}
	if bits > 0 {
		out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
	}
	out
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

/// How long an issued access key stays valid. Deliberately long: the point is that a
/// user authenticates once per device. A key is invalidated early by the operator
/// changing the relay's password / TOTP secret (which rotates the signing key), not by
/// waiting it out.
const KEY_TTL_SECS: u64 = 365 * 24 * 60 * 60;

/// The signing key for access keys, derived from the relay's CURRENT credentials.
///
/// Deriving it from the policy (rather than a random per-process secret) gives two
/// properties for free: issued keys survive a relay restart, and changing the password or
/// the TOTP secret rotates this derivation — instantly invalidating every key the relay
/// ever handed out. That is exactly the "works forever, until the operator changes it"
/// contract, with no key database to store, replicate or revoke.
fn key_signing_secret(auth: &RelayAuth) -> [u8; 32] {
	let mut h = Sha256::new();
	h.update(b"pulsar-relay-access-key-v1");
	h.update(auth.password.as_deref().unwrap_or("").as_bytes());
	h.update(auth.totp_secret.as_deref().unwrap_or(&[]));
	h.finalize().into()
}

/// Mint an access key for `pubkey`: `hex(issued_at_be(8) || mac(16))`, where the MAC
/// covers the issue time AND the device's public key — so the key only ever authenticates
/// the device it was issued to.
pub fn issue_key(auth: &RelayAuth, pubkey: &[u8; 32], unix_time: u64) -> String {
	let secret = key_signing_secret(auth);
	let mac = key_mac(&secret, pubkey, unix_time);
	let mut out = String::with_capacity(48);
	for b in unix_time.to_be_bytes() {
		out.push_str(&format!("{b:02x}"));
	}
	for b in mac {
		out.push_str(&format!("{b:02x}"));
	}
	out
}

/// Is `key` one this relay issued to `pubkey`, under the CURRENT credentials, and still
/// inside [`KEY_TTL_SECS`]? Constant-time MAC compare.
pub fn key_is_valid(auth: &RelayAuth, key: &str, pubkey: &[u8; 32]) -> bool {
	let key = key.trim();
	if key.len() != 48 {
		return false;
	}
	let Some(raw) = hex_decode(key) else {
		return false;
	};
	let mut issued = [0u8; 8];
	issued.copy_from_slice(&raw[..8]);
	let issued_at = u64::from_be_bytes(issued);
	// Reject a key older than the TTL, or one dated absurdly far in the future (a clock
	// jump on the issuing relay shouldn't mint effectively immortal keys).
	let now = unix_now();
	if now.saturating_sub(issued_at) > KEY_TTL_SECS || issued_at.saturating_sub(now) > KEY_TTL_SECS
	{
		return false;
	}
	let secret = key_signing_secret(auth);
	let expected = key_mac(&secret, pubkey, issued_at);
	ct_eq_bytes(&raw[8..], &expected)
}

/// `HMAC-SHA256(signing_secret, pubkey || issued_at)`, truncated to 16 bytes.
fn key_mac(secret: &[u8; 32], pubkey: &[u8; 32], issued_at: u64) -> [u8; 16] {
	use hmac::{Hmac, Mac};
	type HmacSha256 = Hmac<Sha256>;
	let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
	mac.update(pubkey);
	mac.update(&issued_at.to_be_bytes());
	let out = mac.finalize().into_bytes();
	let mut short = [0u8; 16];
	short.copy_from_slice(&out[..16]);
	short
}

/// Current UNIX seconds (0 if the clock is before the epoch).
fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Decode an even-length lowercase/uppercase hex string. `None` on any non-hex byte.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
	if s.len() % 2 != 0 {
		return None;
	}
	let b = s.as_bytes();
	let mut out = Vec::with_capacity(s.len() / 2);
	for pair in b.chunks(2) {
		let hi = (pair[0] as char).to_digit(16)? as u8;
		let lo = (pair[1] as char).to_digit(16)? as u8;
		out.push((hi << 4) | lo);
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

	/// The registering device's public key (access keys are bound to it).
	const PK: [u8; 32] = [0x11; 32];

	#[test]
	fn issued_key_authenticates_without_the_interactive_factors() {
		let secret = [7u8; 32];
		let auth = RelayAuth {
			password: Some("pw".into()),
			..Default::default()
		};
		let t = unix_now();
		// Mint the key the relay would hand back after a successful password auth.
		let key = issue_key(&auth, &PK, t);
		let proof = AuthProof {
			nonce: [0u8; 16],
			password: None,
			totp: None,
			key: Some(key.clone()),
		};
		// The key alone registers the device — no challenge, and no NEW key is minted.
		assert_eq!(
			check(&auth, Some(&proof), &secret, ip(), t, &PK),
			AuthCheck::KeyOk
		);

		// Bound to the device: the same key from a DIFFERENT pubkey is not accepted, and
		// (carrying no interactive factor) simply gets re-challenged.
		let other = [0x22u8; 32];
		assert_eq!(
			check(&auth, Some(&proof), &secret, ip(), t, &other),
			AuthCheck::Challenge {
				password: true,
				totp: false
			}
		);

		// Rotating the relay's credentials invalidates every issued key at once.
		let rotated = RelayAuth {
			password: Some("new-pw".into()),
			..Default::default()
		};
		assert!(!key_is_valid(&rotated, &key, &PK));
		assert_eq!(
			check(&rotated, Some(&proof), &secret, ip(), t, &PK),
			AuthCheck::Challenge {
				password: true,
				totp: false
			}
		);
	}

	#[test]
	fn garbage_and_tampered_keys_are_rejected() {
		let auth = RelayAuth {
			password: Some("pw".into()),
			..Default::default()
		};
		assert!(!key_is_valid(&auth, "", &PK));
		assert!(!key_is_valid(&auth, "not-hex-at-all", &PK));
		let good = issue_key(&auth, &PK, unix_now());
		assert!(key_is_valid(&auth, &good, &PK));
		// Flip the last nibble of the MAC.
		let mut bad = good.clone();
		let last = bad.pop().unwrap();
		bad.push(if last == '0' { '1' } else { '0' });
		assert!(!key_is_valid(&auth, &bad, &PK));
		// A key dated far in the past is expired.
		let old = issue_key(&auth, &PK, unix_now() - (KEY_TTL_SECS + 60));
		assert!(!key_is_valid(&auth, &old, &PK));
	}

	#[test]
	fn open_relay_allows_without_proof() {
		let auth = RelayAuth::default();
		assert_eq!(
			check(&auth, None, &[0u8; 32], ip(), 1000, &PK),
			AuthCheck::Ok
		);
		assert!(!auth.needs_credential());
	}

	#[test]
	fn password_challenge_then_success() {
		let secret = [9u8; 32];
		let auth = RelayAuth {
			password: Some("hunter2".into()),
			..Default::default()
		};
		let t = 1_700_000_000;
		// No proof → challenge for password only.
		assert_eq!(
			check(&auth, None, &secret, ip(), t, &PK),
			AuthCheck::Challenge {
				password: true,
				totp: false
			}
		);
		// Build the proof the client would send from the issued nonce.
		let nonce = challenge_nonce(&secret, ip(), t);
		let good = AuthProof {
			nonce,
			password: Some(pulsar_proto::password_proof(&nonce, "hunter2")),
			totp: None,
			key: None,
		};
		assert_eq!(
			check(&auth, Some(&good), &secret, ip(), t, &PK),
			AuthCheck::Ok
		);
		// Wrong password → Bad.
		let bad = AuthProof {
			nonce,
			password: Some(pulsar_proto::password_proof(&nonce, "wrong")),
			totp: None,
			key: None,
		};
		assert_eq!(
			check(&auth, Some(&bad), &secret, ip(), t, &PK),
			AuthCheck::Bad
		);
	}

	#[test]
	fn stale_nonce_is_rechallenged_not_rejected() {
		let secret = [1u8; 32];
		let auth = RelayAuth {
			password: Some("pw".into()),
			..Default::default()
		};
		let t = 1_700_000_000;
		let old_nonce = challenge_nonce(&secret, ip(), t - 10 * NONCE_STEP); // far in the past
		let proof = AuthProof {
			nonce: old_nonce,
			password: Some(pulsar_proto::password_proof(&old_nonce, "pw")),
			totp: None,
			key: None,
		};
		assert_eq!(
			check(&auth, Some(&proof), &secret, ip(), t, &PK),
			AuthCheck::Challenge {
				password: true,
				totp: false
			}
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
	fn generated_enrollment_is_usable_end_to_end() {
		let e = generate_totp("relay.example.com:21116", "Pulsar");
		// 160-bit secret → 32 base32 chars, decodes back to 20 bytes.
		assert_eq!(e.secret.len(), 32, "160-bit secret is 32 base32 chars");
		let raw = base32_decode(&e.secret).expect("generated secret decodes");
		assert_eq!(raw.len(), 20);
		// The grouped form is the same secret, just spaced for manual entry.
		assert_eq!(e.secret_grouped.replace(' ', ""), e.secret);
		// The URI carries the secret and the explicit parameters.
		assert!(
			e.uri.starts_with("otpauth://totp/Pulsar:"),
			"uri: {}",
			e.uri
		);
		assert!(e.uri.contains(&format!("secret={}", e.secret)));
		assert!(
			e.uri.contains("algorithm=SHA1")
				&& e.uri.contains("digits=6")
				&& e.uri.contains("period=30")
		);
		// The label was percent-encoded (the ':' in host:port must not split the URI).
		assert!(
			e.uri.contains("relay.example.com%3A21116"),
			"uri: {}",
			e.uri
		);
		// Both QR renderings were produced.
		assert!(
			e.qr_svg.contains("<svg") && e.qr_svg.len() > 200,
			"svg head: {}",
			&e.qr_svg[..e.qr_svg.len().min(80)]
		);
		assert!(!e.qr_terminal.is_empty());
		// And a code computed from the generated secret verifies — the whole point.
		let code = hotp(&raw, 1_700_000_000 / TOTP_STEP, 6);
		assert!(totp_valid(&raw, &code, 1_700_000_000));
	}

	#[test]
	fn base32_encode_decode_round_trips() {
		assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
		for len in 1..=24 {
			let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
			let enc = base32_encode(&bytes);
			assert_eq!(
				base32_decode(&enc).unwrap(),
				bytes,
				"round trip at len {len}"
			);
		}
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
			check(&auth, None, &secret, ip(), t, &PK),
			AuthCheck::Challenge {
				password: true,
				totp: true
			}
		);
		let nonce = challenge_nonce(&secret, ip(), t);
		// Right password, missing TOTP → Bad.
		let no_totp = AuthProof {
			nonce,
			password: Some(pulsar_proto::password_proof(&nonce, "pw")),
			totp: None,
			key: None,
		};
		assert_eq!(
			check(&auth, Some(&no_totp), &secret, ip(), t, &PK),
			AuthCheck::Bad
		);
		// Right password + right TOTP → Ok.
		let code = hotp(&totp_secret, t / TOTP_STEP, 6);
		let both = AuthProof {
			nonce,
			password: Some(pulsar_proto::password_proof(&nonce, "pw")),
			totp: Some(code),
			key: None,
		};
		assert_eq!(
			check(&auth, Some(&both), &secret, ip(), t, &PK),
			AuthCheck::Ok
		);
	}
}
