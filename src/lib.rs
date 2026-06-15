//! Pulsar relay / rendezvous server.
//!
//! Responsibilities:
//! 1. **Identity** — assign each device a unique 9-digit [`DeviceId`] + auth [`Token`]
//!    on registration (this is where a device's ID "comes from").
//! 2. **Rendezvous** — when a requester wants to reach a target, hand each side the
//!    other's observed public address so they can **hole-punch a direct P2P path**.
//! 3. **Relay fallback** — if P2P fails, forward already-encrypted payloads between
//!    the two peers ([`ClientMsg::RelayData`]). The relay never holds session keys.
//!
//! The server is a single-task UDP event loop, so its state needs no locking.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use pulsar_proto::{
	decode, encode, ClientMsg, DeviceId, ErrCode, PublicKey, RelayMsg, SessionId, Token,
	MAX_DATAGRAM, PROTOCOL_VERSION,
};
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};

mod limits;

pub use limits::{parse_rate, parse_size, Limits};
use limits::{Meter, METER_TTL};

/// How long a device may go without a heartbeat before it's reaped.
pub const DEVICE_TTL: Duration = Duration::from_secs(30);
/// How long a rendezvous session lingers without traffic.
pub const SESSION_TTL: Duration = Duration::from_secs(120);
/// How long an OFFLINE device keeps its pubkey→id mapping. Long enough that any
/// realistic reconnect gap preserves the user's 9-digit ID, but bounds the map on
/// a long-running public relay with device churn (it would otherwise grow forever).
pub const PUBKEY_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Hard cap on a stored device name (the attacker-controlled `ClientMsg::Register.name`).
/// Registration is unauthenticated, so without a cap a flood of huge names multiplies the
/// per-entry memory of `devices` / `by_pubkey`. Names are only ever a short human label,
/// so anything longer is truncated (on a char boundary) before it's stored.
pub const MAX_NAME_LEN: usize = 64;
/// Upper bound on the number of stable pubkey→id mappings the relay retains. PUBKEY_TTL is
/// 30 days, so without a size cap an unauthenticated Register flood (fresh pubkey each time)
/// could pin the map's memory for a month. Far above any realistic fleet, so it only trips
/// under abuse; when full, the OLDEST mapping whose device is currently OFFLINE is evicted
/// (online devices keep their IDs). A new pubkey is dropped only if every mapping is online.
pub const MAX_PUBKEY_MAPPINGS: usize = 100_000;
/// Hard upper bound on a single `RelayData` payload the relay will forward,
/// enforced UNCONDITIONALLY — independent of the (default-off) operator bandwidth
/// limiter. Without this the relay is a full-rate UDP reflector: any session member
/// can have us blast arbitrarily large datagrams at the other peer. Sessions only
/// carry the small E2E-encrypted control channel (bulk A/V goes direct UDP, never
/// through the relay), so a generous multiple of the MTU-safe `MAX_DATAGRAM` leaves
/// ample headroom for legitimate control payloads + crypto/framing overhead while
/// still capping the reflection/amplification surface. Oversized datagrams are
/// dropped (UDP — the sender's stream adapts).
pub const MAX_RELAY_PAYLOAD: usize = 16 * MAX_DATAGRAM;
/// Hard upper bound on the `hello` handshake blob a `ClientMsg::Connect` may carry, enforced
/// UNCONDITIONALLY (independent of the default-off operator bandwidth limiter). The relay
/// forwards this attacker-controllable blob verbatim inside a `RelayMsg::Incoming` to the
/// target's address, so without a cap any registered device can have us emit a large,
/// hello-padded datagram at a third party — a reflection/amplification primitive. A legitimate
/// `hello` is only `pubkey(32) || salt(32) || optional LAN candidate(6)` ≈ 70 bytes; one
/// MTU-safe datagram leaves ample headroom for that plus any future handshake extension while
/// keeping the forwarded `Incoming` close to the size of the `Connect` that triggered it (no
/// meaningful amplification). Oversized Connects are dropped (UDP — the sender adapts).
pub const MAX_HELLO_LEN: usize = MAX_DATAGRAM;

#[derive(Debug, Clone)]
struct Device {
	addr: SocketAddr,
	token: Token,
	#[allow(dead_code)]
	pubkey: PublicKey,
	#[allow(dead_code)]
	name: Option<String>,
	last_seen: Instant,
}

#[derive(Debug, Clone)]
struct Session {
	requester: DeviceId,
	requester_addr: SocketAddr,
	target: DeviceId,
	target_addr: SocketAddr,
	last_seen: Instant,
}

/// The relay server. Build with [`Relay::bind`], then drive with [`Relay::run`].
pub struct Relay {
	sock: UdpSocket,
	devices: HashMap<DeviceId, Device>,
	sessions: HashMap<SessionId, Session>,
	/// Stable mapping pubkey → (id, last-used) so a returning device keeps the SAME
	/// 9-digit ID across reconnects/restarts (the client persists its identity).
	/// Survives the device's TTL eviction; gc() refreshes entries of registered
	/// devices and reaps mappings offline past [`PUBKEY_TTL`].
	by_pubkey: HashMap<PublicKey, (DeviceId, Instant)>,
	/// Reverse index of every id currently held in [`Self::by_pubkey`], kept exactly in
	/// sync with its value set. Lets id minting test a candidate for collision in O(1)
	/// instead of an O(n) scan of `by_pubkey` — without it a Register flood makes each new
	/// registration cost more CPU as the map grows (a super-linear feedback loop that, on a
	/// single-task event loop, stalls all clients).
	assigned_ids: HashSet<DeviceId>,
	/// Operator bandwidth limits (default: unlimited — see [`Limits`]).
	limits: Limits,
	/// Per-device + per-IP rate/volume meters (only populated when a limit is set).
	user_meters: HashMap<DeviceId, Meter>,
	ip_meters: HashMap<IpAddr, Meter>,
}

impl Relay {
	/// Bind the relay's UDP socket. Pass `127.0.0.1:0` in tests to get an ephemeral port.
	pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
		let sock = UdpSocket::bind(addr).await?;
		Ok(Self {
			sock,
			devices: HashMap::new(),
			sessions: HashMap::new(),
			by_pubkey: HashMap::new(),
			assigned_ids: HashSet::new(),
			limits: Limits::default(),
			user_meters: HashMap::new(),
			ip_meters: HashMap::new(),
		})
	}

	/// Apply operator bandwidth limits (builder; default is unlimited). Used by both the
	/// standalone `pulsar-relay` binary and the desktop app's `--relay` mode.
	pub fn with_limits(mut self, limits: Limits) -> Self {
		self.limits = limits;
		self
	}

	/// The actual bound address (useful after binding to port 0).
	pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
		self.sock.local_addr()
	}

	/// Run the event loop forever (until the socket errors).
	pub async fn run(mut self) -> std::io::Result<()> {
		let mut buf = vec![0u8; 65_536];
		let mut gc = tokio::time::interval(Duration::from_secs(10));
		loop {
			tokio::select! {
				res = self.sock.recv_from(&mut buf) => {
					let (n, from) = match res {
						Ok(v) => v,
						// Per-peer noise, not a socket failure: on Windows an unconnected
						// UDP socket reports a prior send_to's ICMP port-unreachable as
						// ConnectionReset on the NEXT recv_from — any client that exits
						// mid-session would otherwise take the whole relay down.
						Err(e) if matches!(
							e.kind(),
							std::io::ErrorKind::ConnectionReset
								| std::io::ErrorKind::ConnectionRefused
						) => continue,
						Err(e) => return Err(e),
					};
					// One malformed datagram must never take the relay down.
					if let Some((bytes, to)) = self.handle(&buf[..n], from) {
						let _ = self.sock.send_to(&bytes, to).await;
					}
				}
				_ = gc.tick() => self.gc(),
			}
		}
	}

	/// Number of currently-registered devices (for metrics/tests).
	pub fn device_count(&self) -> usize {
		self.devices.len()
	}

	fn now() -> Instant {
		Instant::now()
	}

	/// Handle one datagram, returning an optional `(reply_bytes, dest)` to send.
	/// (Single reply keeps the hot path simple; multi-send cases send inline.)
	fn handle(&mut self, datagram: &[u8], from: SocketAddr) -> Option<(Vec<u8>, SocketAddr)> {
		let msg: ClientMsg = match decode(datagram) {
			Ok(m) => m,
			Err(_) => return None,
		};

		match msg {
			ClientMsg::Register {
				version,
				pubkey,
				name,
			} => {
				// Reject an incompatible wire version up front. The per-session handshake
				// blob format is version-specific (v2 added a 32-byte salt), so a mismatched
				// peer otherwise registers fine and the incompatibility only surfaces later
				// as a misleading rendezvous/handshake TIMEOUT. A typed error here lets the
				// client show a clear "update required" message instead.
				if version != PROTOCOL_VERSION {
					tracing::warn!(%from, version, expected = PROTOCOL_VERSION, "rejecting register: incompatible protocol version");
					return Some((
						Self::err(ErrCode::IncompatibleVersion, "incompatible protocol version"),
						from,
					));
				}
				let (id, token) = self.register(from, pubkey, name);
				tracing::info!(%id, %from, "device registered");
				Some((encode(&RelayMsg::Registered { id, token }), from))
			}

			ClientMsg::Heartbeat { id, token } => {
				if self.authed(id, token) {
					if let Some(dev) = self.devices.get_mut(&id) {
						dev.addr = from;
						dev.last_seen = Self::now();
					}
					tracing::debug!(%id, "heartbeat");
					Some((encode(&RelayMsg::HeartbeatAck), from))
				} else {
					Some((Self::err(ErrCode::NotRegistered, "unknown id/token"), from))
				}
			}

			ClientMsg::Connect {
				id,
				token,
				target,
				session,
				hello,
			} => {
				if !self.authed(id, token) {
					return Some((Self::err(ErrCode::BadToken, "auth failed"), from));
				}
				// Cap the attacker-controllable `hello` blob, enforced UNCONDITIONALLY (like
				// MAX_RELAY_PAYLOAD): it's forwarded verbatim in the Incoming below, so an
				// oversized hello turns Connect into a reflection/amplification primitive
				// toward the target's address. A real handshake is ~70 bytes (see MAX_HELLO_LEN).
				if hello.len() > MAX_HELLO_LEN {
					return None;
				}
				// keep requester's observed addr fresh
				if let Some(dev) = self.devices.get_mut(&id) {
					dev.addr = from;
					dev.last_seen = Self::now();
				}
				let Some(tdev) = self.devices.get(&target).cloned() else {
					return Some((Self::err(ErrCode::TargetOffline, "target not online"), from));
				};
				// Session ownership: a SessionId is bound to the device that first created
				// it. Reject a Connect whose SessionId already exists under a DIFFERENT
				// requester — otherwise any registered device could pick a live session's
				// id and overwrite its record (requester/target/addrs), hijacking the
				// victim's relay path (redirect/blackhole + insert itself as a member).
				// A legitimate retry from the SAME requester (same id) is allowed and just
				// refreshes its own record (new target/addr/hello on re-Connect).
				if let Some(existing) = self.sessions.get(&session) {
					if existing.requester != id {
						return Some((Self::err(ErrCode::Protocol, "session id in use"), from));
					}
				}
				// Charge the forwarded Incoming against the operator bandwidth limits (same
				// meter as RelayData) so Connect-spam counts toward an over-cap sender's
				// per-device / per-source-IP budget instead of being a free reflection path.
				// No-op when no limit is configured (the default).
				// IMPORTANT: evaluated BEFORE sessions.insert so a cap-rejected Connect
				// does not leave a stale session record in the map (the session is never
				// inserted, so there is nothing to clean up on the early return).
				if !self.allow(id, from.ip(), hello.len()) {
					return None;
				}
				self.sessions.insert(
					session,
					Session {
						requester: id,
						requester_addr: from,
						target,
						target_addr: tdev.addr,
						last_seen: Self::now(),
					},
				);
				// Notify the target so it can start hole-punching toward the requester.
				Some((
					encode(&RelayMsg::Incoming {
						from: id,
						from_addr: from,
						session,
						hello,
					}),
					tdev.addr,
				))
			}

			ClientMsg::Accept {
				id,
				token,
				session,
				answer,
			} => {
				if !self.authed(id, token) {
					return Some((Self::err(ErrCode::BadToken, "auth failed"), from));
				}
				// Cap the attacker-controllable `answer` blob, enforced UNCONDITIONALLY (like
				// MAX_RELAY_PAYLOAD and the hello cap on Connect): it's forwarded verbatim in
				// PeerFound below, so an oversized answer turns Accept into a
				// reflection/amplification primitive toward the requester's address — the same
				// surface the hello cap closed on the Connect side. A real answer is the same
				// ~70-byte pubkey||salt as hello (see MAX_HELLO_LEN).
				if answer.len() > MAX_HELLO_LEN {
					return None;
				}
				let Some(sess) = self.sessions.get_mut(&session) else {
					return Some((Self::err(ErrCode::Protocol, "no such session"), from));
				};
				if sess.target != id {
					return Some((Self::err(ErrCode::Protocol, "not the session target"), from));
				}
				sess.target_addr = from;
				sess.last_seen = Self::now();
				let requester_id = sess.requester;
				let requester_addr = sess.requester_addr;
				// Charge the forwarded PeerFound against the operator bandwidth limits so
				// Accept-spam from an over-cap target counts toward its per-device / per-IP
				// budget instead of being a free reflection path — mirrors the allow() call on
				// the Connect side. No-op when no limit is configured (the default).
				if !self.allow(id, from.ip(), answer.len()) {
					return None;
				}
				let _ = requester_id; // used for symmetry with Connect; may wire to metrics later
				// Tell the requester the target accepted, with the target's address.
				Some((
					encode(&RelayMsg::PeerFound {
						target: id,
						target_addr: from,
						session,
						answer,
					}),
					requester_addr,
				))
			}

			ClientMsg::RelayData {
				id,
				token,
				session,
				payload,
			} => {
				if !self.authed(id, token) {
					return Some((Self::err(ErrCode::BadToken, "auth failed"), from));
				}
				// Hard payload cap, enforced regardless of operator bandwidth limits (which
				// are off by default): drop oversized datagrams so the relay can't be used as
				// a full-rate UDP reflector/amplifier toward a session peer. Sessions carry
				// only the small control channel — anything this large is abuse or a bug.
				if payload.len() > MAX_RELAY_PAYLOAD {
					return None;
				}
				// Resolve the other end of the session (scoped so the borrow ends before
				// the rate-limit check below mutates the meter maps).
				let dest = {
					let Some(sess) = self.sessions.get_mut(&session) else {
						return Some((Self::err(ErrCode::Protocol, "no such session"), from));
					};
					sess.last_seen = Self::now();
					if id == sess.requester {
						sess.target_addr
					} else if id == sess.target {
						sess.requester_addr
					} else {
						return Some((Self::err(ErrCode::Protocol, "not a session member"), from));
					}
				};
				// Operator bandwidth limits: silently drop (don't forward) when the
				// sending device / source IP is over its rate or volume cap.
				if !self.allow(id, from.ip(), payload.len()) {
					return None;
				}
				Some((encode(&RelayMsg::RelayData { session, payload }), dest))
			}

			ClientMsg::Bye { id, token } => {
				if self.authed(id, token) {
					self.devices.remove(&id);
					self.sessions
						.retain(|_, s| s.requester != id && s.target != id);
				}
				None
			}
		}
	}

	fn register(
		&mut self,
		addr: SocketAddr,
		pubkey: PublicKey,
		name: Option<String>,
	) -> (DeviceId, Token) {
		// Registration is unauthenticated, so a flood of distinct pubkeys would otherwise
		// inflate `devices` / `by_pubkey`. Three bounds keep that flood cheap and capped:
		// (1) id minting checks `assigned_ids` in O(1) instead of an O(n) scan of `by_pubkey`
		//     (the scan made each registration cost more as the map grew — a super-linear
		//     feedback loop that stalls the single-task event loop under churn);
		// (2) the attacker-controlled `name` is truncated to MAX_NAME_LEN before storage so a
		//     single entry can't pin unbounded memory;
		// (3) `by_pubkey` is capped at MAX_PUBKEY_MAPPINGS so the 30-day PUBKEY_TTL can't let
		//     churn pin the map for a month — when full we evict the oldest OFFLINE mapping.
		let mut rng = rand::thread_rng();
		let now = Self::now();
		let name = name.map(|mut n| {
			if n.len() > MAX_NAME_LEN {
				// Truncate on a char boundary so multi-byte UTF-8 names don't panic.
				let cut = (0..=MAX_NAME_LEN)
					.rev()
					.find(|&i| n.is_char_boundary(i))
					.unwrap_or(0);
				n.truncate(cut);
			}
			n
		});
		// A device that registered before (same persisted identity) keeps its id, so
		// the user's 9-digit ID is stable across restarts. Only mint a new id for a
		// pubkey we've never seen (or one reaped after PUBKEY_TTL offline).
		let id = match self.by_pubkey.get_mut(&pubkey) {
			Some(entry) => {
				entry.1 = now;
				entry.0
			}
			None => {
				// Bound the map: if it's full, drop the oldest OFFLINE mapping to make room
				// (online devices keep their IDs). If every mapping is online (no abuse), we
				// just let the map exceed the cap rather than rotate a live device's ID.
				if self.by_pubkey.len() >= MAX_PUBKEY_MAPPINGS {
					self.evict_oldest_offline_mapping();
				}
				let fresh = loop {
					let candidate = DeviceId::random(&mut rng);
					if !self.assigned_ids.contains(&candidate) {
						break candidate;
					}
				};
				self.by_pubkey.insert(pubkey, (fresh, now));
				self.assigned_ids.insert(fresh);
				fresh
			}
		};
		let token = Token::random(&mut rng);
		self.devices.insert(
			id,
			Device {
				addr,
				token,
				pubkey,
				name,
				last_seen: Self::now(),
			},
		);
		(id, token)
	}

	/// Make room in [`Self::by_pubkey`] when it has hit [`MAX_PUBKEY_MAPPINGS`]: evict the
	/// oldest (least-recently-used) mapping whose device is NOT currently registered. Online
	/// devices are never rotated, so a returning device keeps its stable ID; only stale
	/// offline mappings (the bulk of a flood) are dropped. Does nothing if every mapping is
	/// online (the map is then allowed to exceed the cap rather than disrupt a live device).
	fn evict_oldest_offline_mapping(&mut self) {
		let devices = &self.devices;
		let victim = self
			.by_pubkey
			.iter()
			.filter(|(_, (id, _))| !devices.contains_key(id))
			.min_by_key(|(_, (_, last))| *last)
			.map(|(pk, (id, _))| (*pk, *id));
		if let Some((pk, id)) = victim {
			self.by_pubkey.remove(&pk);
			self.assigned_ids.remove(&id);
		}
	}

	fn authed(&self, id: DeviceId, token: Token) -> bool {
		self.devices.get(&id).is_some_and(|d| d.token.ct_eq(&token))
	}

	/// Charge a `sz`-byte relayed datagram (from device `id` / source `ip`) against the
	/// operator limits. Returns false when over the rate or volume cap; the caller then
	/// drops the datagram. No-op (always true) when no limit is configured.
	fn allow(&mut self, id: DeviceId, ip: IpAddr, sz: usize) -> bool {
		if self.limits.is_unlimited() {
			return true;
		}
		let now = Self::now();
		let sz = sz as u64;
		let (ubps, utot) = (self.limits.per_user_bps, self.limits.per_user_total);
		let (ibps, itot) = (self.limits.per_ip_bps, self.limits.per_ip_total);
		let user_active = ubps.is_some() || utot.is_some();
		let ip_active = ibps.is_some() || itot.is_some();
		// Dry-run both meters against the SAME `now` before charging either, so a reject by
		// one meter never consumes rate-bucket tokens / volume from the other. (Charging the
		// user meter first and only then discovering the IP meter rejects would otherwise
		// burn a device's own cap for bytes the relay never forwarded.)
		if user_active {
			let m = self
				.user_meters
				.entry(id)
				.or_insert_with(|| Meter::new(now));
			// Every consult counts as activity, REJECTED datagrams included: an over-cap
			// sender that keeps transmitting must not let its meter go "idle", get reaped
			// by gc(), and be reborn with a fresh volume allowance every METER_TTL.
			m.last_active = now;
			if !m.would_allow(now, sz, ubps, utot) {
				return false;
			}
		}
		if ip_active {
			let m = self.ip_meters.entry(ip).or_insert_with(|| Meter::new(now));
			m.last_active = now;
			if !m.would_allow(now, sz, ibps, itot) {
				return false;
			}
		}
		// Both approved → commit. The same `now` makes each refill an identical no-op delta.
		if user_active {
			self.user_meters
				.get_mut(&id)
				.unwrap()
				.charge(now, sz, ubps, utot);
		}
		if ip_active {
			self.ip_meters
				.get_mut(&ip)
				.unwrap()
				.charge(now, sz, ibps, itot);
		}
		true
	}

	fn err(code: ErrCode, message: &str) -> Vec<u8> {
		encode(&RelayMsg::Error {
			code,
			message: message.to_string(),
		})
	}

	/// Drop stale devices and sessions.
	fn gc(&mut self) {
		self.gc_at(Self::now());
	}

	/// [`Self::gc`] against an explicit `now`, so tests can drive long horizons.
	fn gc_at(&mut self, now: Instant) {
		self.devices
			.retain(|_, d| now.duration_since(d.last_seen) < DEVICE_TTL);
		self.sessions
			.retain(|_, s| now.duration_since(s.last_seen) < SESSION_TTL);
		// The stable-ID map: keep refreshing entries whose device is still registered
		// (a host online for months must not lose its mapping), and reap entries that
		// have been offline past PUBKEY_TTL so the map stays bounded under churn. Keep the
		// `assigned_ids` reverse index in lock-step: drop the id of every reaped mapping.
		let devices = &self.devices;
		let assigned_ids = &mut self.assigned_ids;
		self.by_pubkey.retain(|_, e| {
			if devices.contains_key(&e.0) {
				e.1 = now;
				true
			} else if now.saturating_duration_since(e.1) < PUBKEY_TTL {
				true
			} else {
				assigned_ids.remove(&e.0);
				false
			}
		});
		// Reap idle rate-limit meters so the maps don't grow unbounded.
		self.user_meters
			.retain(|_, m| now.saturating_duration_since(m.last_active) < METER_TTL);
		self.ip_meters
			.retain(|_, m| now.saturating_duration_since(m.last_active) < METER_TTL);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn stable_id_survives_offline_gap_but_pubkey_ttl_bounds_the_map() {
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
		let addr: SocketAddr = "203.0.113.9:1000".parse().unwrap();
		let pk: PublicKey = [7u8; 32];
		let t0 = Instant::now();
		let (id, _) = relay.register(addr, pk, None);
		// A day offline: the device itself is long evicted, but the pubkey→id
		// mapping survives, so re-registering yields the SAME 9-digit ID.
		let day = Duration::from_secs(24 * 60 * 60);
		relay.gc_at(t0 + day);
		assert_eq!(relay.device_count(), 0, "offline device must be evicted");
		let (id2, _) = relay.register(addr, pk, None);
		assert_eq!(id, id2, "id must be stable across an offline gap");
		// Offline past PUBKEY_TTL: the mapping is reaped so the map stays bounded.
		relay.gc_at(t0 + day + PUBKEY_TTL + Duration::from_secs(1));
		assert!(
			relay.by_pubkey.is_empty(),
			"stale pubkey mapping must be reaped"
		);
	}

	// A SessionId is owned by its creating requester: a second device can't reuse a
	// live session's id to overwrite (hijack) its record. The owner's own retry can.
	#[tokio::test]
	async fn connect_cannot_hijack_another_devices_session_id() {
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
		let a: SocketAddr = "203.0.113.1:1".parse().unwrap();
		let b: SocketAddr = "203.0.113.2:2".parse().unwrap();
		let c: SocketAddr = "203.0.113.3:3".parse().unwrap();
		let (a_id, a_tok) = relay.register(a, [1u8; 32], None);
		let (b_id, _b_tok) = relay.register(b, [2u8; 32], None);
		let (c_id, c_tok) = relay.register(c, [3u8; 32], None);
		let session: SessionId = 0xABCD;

		// A → B establishes the session.
		let connect = |id, token, target, addr: SocketAddr| {
			move |relay: &mut Relay| {
				relay.handle(
					&encode(&ClientMsg::Connect {
						id,
						token,
						target,
						session,
						hello: vec![],
					}),
					addr,
				)
			}
		};
		assert!(connect(a_id, a_tok, b_id, a)(&mut relay).is_some());
		let sess = relay.sessions.get(&session).cloned().unwrap();
		assert_eq!(sess.requester, a_id);

		// C tries to hijack the SAME session id → rejected, record untouched.
		let reply = connect(c_id, c_tok, b_id, c)(&mut relay);
		assert!(reply.is_some(), "hijack attempt should get an error reply");
		let after = relay.sessions.get(&session).unwrap();
		assert_eq!(after.requester, a_id, "owner's session must be unchanged");
		assert_ne!(after.requester, c_id, "attacker must not become the requester");

		// A's own retry (same requester) is allowed and refreshes the record.
		assert!(connect(a_id, a_tok, b_id, a)(&mut relay).is_some());
		assert_eq!(relay.sessions.get(&session).unwrap().requester, a_id);
	}

	// An over-long, attacker-controlled `hello` blob on a Connect is dropped (no Incoming
	// forwarded), so Connect can't be used to reflect a large hello-padded datagram at the
	// target. A normal-sized hello is still forwarded verbatim.
	#[tokio::test]
	async fn connect_caps_hello_blob_and_drops_oversized() {
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
		let a: SocketAddr = "203.0.113.1:1".parse().unwrap();
		let b: SocketAddr = "203.0.113.2:2".parse().unwrap();
		let (a_id, a_tok) = relay.register(a, [1u8; 32], None);
		let (b_id, _b_tok) = relay.register(b, [2u8; 32], None);
		let connect = |hello: Vec<u8>, session: SessionId, relay: &mut Relay| {
			relay.handle(
				&encode(&ClientMsg::Connect {
					id: a_id,
					token: a_tok,
					target: b_id,
					session,
					hello,
				}),
				a,
			)
		};
		// Oversized hello → dropped (no reply, no session created, nothing forwarded).
		let huge = vec![0u8; MAX_HELLO_LEN + 1];
		assert!(connect(huge, 0x1111, &mut relay).is_none(), "oversized hello must be dropped");
		assert!(!relay.sessions.contains_key(&0x1111), "no session for a dropped Connect");
		// A realistic hello (pubkey||salt||LAN ≈ 70 B) is forwarded to the target's address.
		let (reply, to) = connect(vec![7u8; 70], 0x2222, &mut relay).expect("normal hello forwarded");
		assert_eq!(to, b, "Incoming goes to the target's last-seen address");
		match decode(&reply).unwrap() {
			RelayMsg::Incoming { hello, .. } => assert_eq!(hello, vec![7u8; 70]),
			other => panic!("expected Incoming, got {other:?}"),
		}
	}

	// An over-long, attacker-controlled `answer` blob on an Accept is dropped (no PeerFound
	// forwarded), so Accept can't be used to reflect a large answer-padded datagram at the
	// requester. This is the symmetric cap to connect_caps_hello_blob_and_drops_oversized.
	// A normal-sized answer is still forwarded verbatim.
	#[tokio::test]
	async fn accept_caps_answer_blob_and_drops_oversized() {
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
		let a: SocketAddr = "203.0.113.1:1".parse().unwrap();
		let b: SocketAddr = "203.0.113.2:2".parse().unwrap();
		let (a_id, a_tok) = relay.register(a, [1u8; 32], None);
		let (b_id, b_tok) = relay.register(b, [2u8; 32], None);
		let session: SessionId = 0xBEEF;

		// Establish the session: A connects to B.
		relay.handle(
			&encode(&ClientMsg::Connect {
				id: a_id,
				token: a_tok,
				target: b_id,
				session,
				hello: vec![7u8; 70],
			}),
			a,
		);
		assert!(relay.sessions.contains_key(&session), "session must exist after Connect");

		// B (the target) sends an oversized answer → must be dropped, no PeerFound emitted.
		let huge_answer = vec![0u8; MAX_HELLO_LEN + 1];
		let reply = relay.handle(
			&encode(&ClientMsg::Accept {
				id: b_id,
				token: b_tok,
				session,
				answer: huge_answer,
			}),
			b,
		);
		assert!(reply.is_none(), "oversized answer must be dropped — no PeerFound emitted");

		// B sends a normal-sized answer → PeerFound must reach the requester's address.
		let reply = relay.handle(
			&encode(&ClientMsg::Accept {
				id: b_id,
				token: b_tok,
				session,
				answer: vec![9u8; 70],
			}),
			b,
		);
		let (reply_bytes, to) = reply.expect("normal answer must produce a PeerFound reply");
		assert_eq!(to, a, "PeerFound goes to the requester's last-seen address");
		match decode(&reply_bytes).unwrap() {
			RelayMsg::PeerFound { answer, .. } => assert_eq!(answer, vec![9u8; 70]),
			other => panic!("expected PeerFound, got {other:?}"),
		}
	}

	// An over-long (attacker-controlled) device name is truncated to MAX_NAME_LEN before
	// storage so a Register flood can't pin unbounded per-entry memory. Truncation is on a
	// char boundary so multi-byte UTF-8 names never panic.
	#[tokio::test]
	async fn register_caps_stored_name_length() {
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
		let addr: SocketAddr = "203.0.113.9:1000".parse().unwrap();
		let huge = "a".repeat(10_000);
		let (id, _) = relay.register(addr, [1u8; 32], Some(huge));
		let stored = relay.devices.get(&id).unwrap().name.as_ref().unwrap();
		assert!(stored.len() <= MAX_NAME_LEN, "name must be capped");
		// A multi-byte name truncated near the cap must stay valid UTF-8 (no panic, no split
		// codepoint): 'ş' is 2 bytes, so MAX_NAME_LEN/2 + a few of them straddle the cap.
		let multibyte = "ş".repeat(MAX_NAME_LEN); // 2*MAX_NAME_LEN bytes
		let (id2, _) = relay.register("203.0.113.9:1001".parse().unwrap(), [2u8; 32], Some(multibyte));
		let stored2 = relay.devices.get(&id2).unwrap().name.as_ref().unwrap();
		assert!(stored2.len() <= MAX_NAME_LEN);
		assert!(stored2.chars().all(|c| c == 'ş'), "must not split a codepoint");
	}

	// The reverse index stays in lock-step with by_pubkey so minted ids are unique and the
	// O(1) collision check never produces a duplicate. Re-registering a known pubkey keeps
	// its id and does NOT grow the index; gc reaping a stale mapping shrinks it.
	#[tokio::test]
	async fn assigned_ids_mirrors_by_pubkey_value_set() {
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
		let t0 = Instant::now();
		let (id_a, _) = relay.register("203.0.113.1:1".parse().unwrap(), [1u8; 32], None);
		let (id_b, _) = relay.register("203.0.113.2:2".parse().unwrap(), [2u8; 32], None);
		assert_ne!(id_a, id_b, "fresh pubkeys must get distinct ids");
		assert_eq!(relay.assigned_ids.len(), 2);
		// Re-registering pubkey A keeps its id and does not grow the index.
		let (id_a2, _) = relay.register("203.0.113.1:9".parse().unwrap(), [1u8; 32], None);
		assert_eq!(id_a, id_a2);
		assert_eq!(relay.assigned_ids.len(), 2);
		assert!(relay.assigned_ids.contains(&id_a) && relay.assigned_ids.contains(&id_b));
		// After both devices go offline past PUBKEY_TTL, gc reaps the mappings AND the index.
		relay.gc_at(t0 + PUBKEY_TTL + Duration::from_secs(1));
		assert!(relay.by_pubkey.is_empty());
		assert!(relay.assigned_ids.is_empty(), "reverse index must track reaping");
	}

	// When by_pubkey hits its size cap, registering a fresh pubkey evicts the OLDEST OFFLINE
	// mapping — never an online device's — so a flood can't grow the map without bound while
	// live devices keep their stable IDs.
	#[tokio::test]
	async fn full_pubkey_map_evicts_oldest_offline_not_online() {
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
		let addr: SocketAddr = "203.0.113.9:1".parse().unwrap();
		let t0 = Instant::now();
		// One online device (its device record is live) registered first = oldest mapping.
		let online_pk: PublicKey = [0xAA; 32];
		let (online_id, _) = relay.register(addr, online_pk, None);
		// Fill the map to the cap with OFFLINE mappings (device records removed), each with a
		// later last-used time than the online one so the online one is the oldest overall.
		while relay.by_pubkey.len() < MAX_PUBKEY_MAPPINGS {
			let mut pk = [0u8; 32];
			let i = relay.by_pubkey.len() as u32;
			pk[..4].copy_from_slice(&i.to_le_bytes());
			let (id, _) = relay.register(addr, pk, None);
			relay.devices.remove(&id); // make it offline
		}
		assert_eq!(relay.by_pubkey.len(), MAX_PUBKEY_MAPPINGS);
		// One more fresh pubkey: must evict an offline mapping (not the online one), so the
		// map stays at the cap and the online device keeps its id.
		let (new_id, _) = relay.register(addr, [0xBB; 32], None);
		assert_eq!(relay.by_pubkey.len(), MAX_PUBKEY_MAPPINGS, "map stays capped");
		assert!(
			relay.by_pubkey.values().any(|&(v, _)| v == online_id),
			"online device's mapping must survive eviction"
		);
		assert!(relay.assigned_ids.contains(&new_id));
		let _ = t0;
	}
}
