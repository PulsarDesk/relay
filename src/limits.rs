//! Operator bandwidth limiting: rate/size parsing, [`Limits`], and the per-key
//! token-bucket + running-total [`Meter`] applied to relayed traffic.

use tokio::time::{Duration, Instant};

/// How long a rate-limit meter lingers without traffic before it's reaped.
pub(crate) const METER_TTL: Duration = Duration::from_secs(120);

/// Operator-configurable bandwidth limits applied to **relayed** traffic
/// (`ClientMsg::RelayData` — the bytes the relay forwards between peers). Every field
/// is `None` by default = **unlimited**; an operator self-hosting a relay can cap the
/// forwarding rate (bytes/second) and/or the cumulative data volume (bytes), per
/// **device** (`per_user_*`) and/or per **source IP** (`per_ip_*`). When a limit is hit
/// the offending datagram is silently dropped (the stream is UDP and adapts).
///
/// Shared by the standalone `pulsar-relay` binary and the desktop app's `--relay` mode
/// (both run this same [`crate::Relay`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct Limits {
	/// Max forward rate per device, bytes/second.
	pub per_user_bps: Option<u64>,
	/// Max cumulative forwarded volume per device, bytes (since it was first metered).
	pub per_user_total: Option<u64>,
	/// Max forward rate per source IP, bytes/second.
	pub per_ip_bps: Option<u64>,
	/// Max cumulative forwarded volume per source IP, bytes.
	pub per_ip_total: Option<u64>,
	/// Max forward rate per **relay SESSION**, bytes/second. Unlike the per-device/per-IP
	/// axes (which a multi-session device shares across all its traffic), this caps EACH
	/// session independently — so two split-screen panes from one device each get the full
	/// budget, and the cap maps cleanly to one stream's bitrate. It also doubles as the
	/// **encoder hint** the relay advertises in `PeerFound.rate_cap_kbps`, letting a relayed
	/// client start at/below the cap instead of overshooting (see `session_cap_kbps`).
	pub per_session_bps: Option<u64>,
	/// Max cumulative forwarded volume per relay session, bytes.
	pub per_session_total: Option<u64>,
}

impl Limits {
	/// True if no limit is set (the common case — skip all metering on the hot path).
	pub(crate) fn is_unlimited(&self) -> bool {
		self.per_user_bps.is_none()
			&& self.per_user_total.is_none()
			&& self.per_ip_bps.is_none()
			&& self.per_ip_total.is_none()
			&& self.per_session_bps.is_none()
			&& self.per_session_total.is_none()
	}
}

/// A token-bucket + running-total meter for one key (a device id or a source IP).
#[derive(Debug)]
pub(crate) struct Meter {
	/// Available bytes in the rate bucket (refilled at `bps`, capped at a 1-second burst
	/// or the current datagram size, whichever is larger, so a single full-size datagram
	/// can always eventually pass even for sub-MTU rates).
	tokens: f64,
	/// Last time the bucket was refilled.
	last: Instant,
	/// Cumulative forwarded bytes (for the volume cap).
	total: u64,
	/// Last time this meter saw traffic (for GC).
	pub(crate) last_active: Instant,
}

impl Meter {
	pub(crate) fn new(now: Instant) -> Self {
		// Start the bucket full (last = ~1s ago) so the first datagram isn't dropped.
		Self {
			tokens: 0.0,
			last: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
			total: 0,
			last_active: now,
		}
	}

	/// Refilled token count projected to `now` WITHOUT persisting (`self.last`/`self.tokens`
	/// unchanged). The burst cap is `max(1s of rate, sz)` so a single datagram larger than
	/// one second of rate can still eventually pass (otherwise sub-MTU rates drop forever).
	fn projected_tokens(&self, now: Instant, sz: u64, rate: u64) -> f64 {
		let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
		(self.tokens + elapsed * rate as f64).min((rate as f64).max(sz as f64))
	}

	/// Non-mutating check: would charging `sz` bytes pass both the rate bucket and the
	/// volume cap? Computes the projected token count from `now` but writes nothing, so the
	/// caller can verify several meters before committing any of them. Pair with the same
	/// `now` in [`charge`] so the committing refill is an identical no-op delta.
	pub(crate) fn would_allow(
		&self,
		now: Instant,
		sz: u64,
		bps: Option<u64>,
		total: Option<u64>,
	) -> bool {
		if let Some(cap) = total {
			if self.total.saturating_add(sz) > cap {
				return false;
			}
		}
		if let Some(rate) = bps {
			if self.projected_tokens(now, sz, rate) < sz as f64 {
				return false;
			}
		}
		true
	}

	/// Charge `sz` bytes against this meter; returns false (drop) if it would exceed the
	/// rate bucket or the volume cap. A dropped datagram is NOT counted toward the total.
	pub(crate) fn charge(
		&mut self,
		now: Instant,
		sz: u64,
		bps: Option<u64>,
		total: Option<u64>,
	) -> bool {
		self.last_active = now;
		if let Some(cap) = total {
			if self.total.saturating_add(sz) > cap {
				return false;
			}
		}
		if let Some(rate) = bps {
			self.tokens = self.projected_tokens(now, sz, rate);
			self.last = now;
			if self.tokens < sz as f64 {
				return false;
			}
			self.tokens -= sz as f64;
		}
		self.total = self.total.saturating_add(sz);
		true
	}
}

/// Parse a transfer-RATE string into **bytes per second**. Bit units (`bit`/`kbit`/
/// `mbit`/`gbit`, `bps`/`kbps`/`mbps`/`gbps`, or bare `k`/`m`/`g`) follow the networking
/// convention; byte units (`b`/`kb`/`mb`/`gb`, `byte`/`kbyte`/…) are bytes. e.g.
/// `"10mbit"` → 1_250_000, `"10mb"` → 10_000_000. Case-insensitive. `None` if malformed.
pub fn parse_rate(s: &str) -> Option<u64> {
	let (n, unit) = split_num_unit(s)?;
	let v = match unit.as_str() {
		"" | "b" | "byte" | "bytes" | "b/s" => n,
		"kb" | "kbyte" | "kb/s" => n * 1e3,
		"mb" | "mbyte" | "mb/s" => n * 1e6,
		"gb" | "gbyte" | "gb/s" => n * 1e9,
		"bit" | "bps" | "bit/s" => n / 8.0,
		"k" | "kbit" | "kbps" | "kbit/s" => n * 1e3 / 8.0,
		"m" | "mbit" | "mbps" | "mbit/s" => n * 1e6 / 8.0,
		"g" | "gbit" | "gbps" | "gbit/s" => n * 1e9 / 8.0,
		_ => return None,
	};
	Some(v as u64)
}

/// Parse a data-SIZE string into **bytes** (`kb`/`mb`/`gb`/`tb` = 1000-based, `kib`/
/// `mib`/`gib` = 1024-based, bare `k`/`m`/`g`/`t` = 1000-based). `None` if malformed.
pub fn parse_size(s: &str) -> Option<u64> {
	let (n, unit) = split_num_unit(s)?;
	let v = match unit.as_str() {
		"" | "b" | "byte" | "bytes" => n,
		"k" | "kb" => n * 1e3,
		"m" | "mb" => n * 1e6,
		"g" | "gb" => n * 1e9,
		"t" | "tb" => n * 1e12,
		"kib" => n * 1024.0,
		"mib" => n * 1024.0 * 1024.0,
		"gib" => n * 1024.0 * 1024.0 * 1024.0,
		_ => return None,
	};
	Some(v as u64)
}

/// Split "10mbit" → (10.0, "mbit"). Lower-cases + trims the unit.
fn split_num_unit(s: &str) -> Option<(f64, String)> {
	let s = s.trim();
	let pos = s
		.find(|c: char| !(c.is_ascii_digit() || c == '.'))
		.unwrap_or(s.len());
	let n: f64 = s[..pos].parse().ok()?;
	if n < 0.0 {
		return None;
	}
	Some((n, s[pos..].trim().to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rate_parsing_units() {
		assert_eq!(parse_rate("10mbit"), Some(1_250_000)); // 10 Mbit/s = 1.25 MB/s
		assert_eq!(parse_rate("10mb"), Some(10_000_000)); // 10 MB/s (bytes)
		assert_eq!(parse_rate("1gbit"), Some(125_000_000));
		assert_eq!(parse_rate("500kbit"), Some(62_500));
		assert_eq!(parse_rate("2m"), Some(250_000)); // bare m = mbit
		assert_eq!(parse_rate("1000"), Some(1000)); // bare number = bytes/s
		assert_eq!(parse_rate("bogus"), None);
		assert_eq!(parse_rate("-5mbit"), None);
	}

	#[test]
	fn size_parsing_units() {
		assert_eq!(parse_size("5gb"), Some(5_000_000_000));
		assert_eq!(parse_size("500mb"), Some(500_000_000));
		assert_eq!(parse_size("1gib"), Some(1_073_741_824));
		assert_eq!(parse_size("1024"), Some(1024)); // bare = bytes
		assert_eq!(parse_size("nope"), None);
	}

	#[test]
	fn default_limits_are_unlimited() {
		assert!(Limits::default().is_unlimited());
	}

	#[test]
	fn token_bucket_caps_rate() {
		let t0 = Instant::now();
		let mut m = Meter::new(t0);
		// 1000 B/s rate, no volume cap. The bucket starts full (~1s burst) so the first
		// 1000 bytes pass, then further bytes in the same instant are dropped.
		assert!(m.charge(t0, 1000, Some(1000), None));
		assert!(!m.charge(t0, 1, Some(1000), None)); // bucket empty → dropped
											   // After ~1s the bucket refills enough for another 1000 bytes.
		let t1 = t0 + Duration::from_secs(1);
		assert!(m.charge(t1, 1000, Some(1000), None));
	}

	#[test]
	fn volume_cap_blocks_over_total_and_doesnt_count_drops() {
		let t0 = Instant::now();
		let mut m = Meter::new(t0);
		assert!(m.charge(t0, 800, None, Some(1000)));
		assert!(!m.charge(t0, 800, None, Some(1000))); // 800+800 > 1000 → dropped
		assert_eq!(m.total, 800); // the dropped datagram was NOT counted
		assert!(m.charge(t0, 200, None, Some(1000))); // 800+200 == 1000 → ok
		assert_eq!(m.total, 1000);
	}

	#[test]
	fn sub_mtu_rate_eventually_passes_a_full_datagram() {
		// Rate (1250 B/s) below a full datagram (1400 B): the old 1-second burst cap
		// pinned tokens at 1250 < 1400 forever, so every full datagram dropped. The burst
		// cap is now max(1s of rate, sz), so a 1400-byte datagram passes after ~sz/rate s.
		let t0 = Instant::now();
		let mut m = Meter::new(t0);
		// Drain the initial burst, then a full datagram must still be possible later.
		assert!(!m.charge(t0, 1400, Some(1250), None)); // 1.12s of rate not yet accrued
		let t1 = t0 + Duration::from_secs(2); // enough elapsed time to fill for one datagram
		assert!(m.charge(t1, 1400, Some(1250), None)); // no longer permanently dropped
	}

	#[test]
	fn would_allow_does_not_mutate_state() {
		// Underpins the allow() double-counting fix: a dry-run check must consume no
		// tokens and no volume, so a reject by a sibling meter never charges this one.
		let t0 = Instant::now();
		let mut m = Meter::new(t0);
		assert!(m.charge(t0, 1000, Some(1000), Some(10_000)));
		let tokens_before = m.tokens;
		let total_before = m.total;
		let last_before = m.last;
		// Several dry-runs change nothing.
		for _ in 0..3 {
			let _ = m.would_allow(t0, 500, Some(1000), Some(10_000));
		}
		assert_eq!(m.tokens, tokens_before);
		assert_eq!(m.total, total_before);
		assert_eq!(m.last, last_before);
	}
}
