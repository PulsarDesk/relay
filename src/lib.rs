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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use pulsar_proto::{
	decode, encode, ClientMsg, DeviceId, ErrCode, PublicKey, RelayMsg, SessionId, Token,
	MAX_DATAGRAM,
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
				version: _,
				pubkey,
				name,
			} => {
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
				let Some(sess) = self.sessions.get_mut(&session) else {
					return Some((Self::err(ErrCode::Protocol, "no such session"), from));
				};
				if sess.target != id {
					return Some((Self::err(ErrCode::Protocol, "not the session target"), from));
				}
				sess.target_addr = from;
				sess.last_seen = Self::now();
				let requester_addr = sess.requester_addr;
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
		// TODO(security, low priority): registration is unauthenticated, so a flood of
		// distinct pubkeys can grow `devices` / `by_pubkey` until DEVICE_TTL / PUBKEY_TTL
		// reap them (PUBKEY_TTL is 30 days → a sustained churn attack inflates the map for
		// a long time). A proper fix is a per-IP registration rate/quota meter (reuse the
		// `Meter` infra) or a lightweight proof-of-work on Register. Not trivial to do well
		// (NAT shares IPs; PoW needs a proto change), so deferred rather than half-done here.
		let mut rng = rand::thread_rng();
		let now = Self::now();
		// A device that registered before (same persisted identity) keeps its id, so
		// the user's 9-digit ID is stable across restarts. Only mint a new id for a
		// pubkey we've never seen (or one reaped after PUBKEY_TTL offline).
		let id = match self.by_pubkey.get_mut(&pubkey) {
			Some(entry) => {
				entry.1 = now;
				entry.0
			}
			None => {
				let fresh = loop {
					let candidate = DeviceId::random(&mut rng);
					if !self.devices.contains_key(&candidate)
						&& !self.by_pubkey.values().any(|&(v, _)| v == candidate)
					{
						break candidate;
					}
				};
				self.by_pubkey.insert(pubkey, (fresh, now));
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

	fn authed(&self, id: DeviceId, token: Token) -> bool {
		self.devices.get(&id).is_some_and(|d| d.token == token)
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
		// have been offline past PUBKEY_TTL so the map stays bounded under churn.
		let devices = &self.devices;
		self.by_pubkey.retain(|_, e| {
			if devices.contains_key(&e.0) {
				e.1 = now;
				true
			} else {
				now.saturating_duration_since(e.1) < PUBKEY_TTL
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
}
