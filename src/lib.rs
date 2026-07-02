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

use std::net::{IpAddr, SocketAddr};

// B12: ahash for the hot registry/meter maps. AHashMap/AHashSet are randomly seeded
// per process, so they stay DoS-resistant against an attacker who picks colliding
// SessionIds (the reason we do NOT use a deterministic FxHash here) while being
// faster than the std SipHash default on this single-task hot path.
use ahash::{AHashMap, AHashSet};

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
/// can have us blast arbitrarily large datagrams at the other peer.
///
/// The bound must accommodate the worst-case legitimate `DataMsg`: the identity
/// avatar (≤ `MAX_AVATAR_BYTES` = 14 000 raw bytes, defined in `src-tauri/src/avatar.rs`).
/// `DataMsg` is serialized with `serde_json`, which encodes a `Vec<u8>` as a JSON
/// decimal-number array — roughly 3.57–4 chars per byte for arbitrary binary data —
/// so 14 000 raw bytes expand to ≈ 50–56 KB of JSON.  Add ChaCha20-Poly1305 seal
/// (+16 bytes) and bincode `PeerMsg::Data` / `RelayData` framing (tens of bytes) and
/// the sealed payload the relay sees is ≈ 57 KB at most.  64 KB gives a comfortable
/// margin while still capping the reflection/amplification surface below a single UDP
/// maximum (65 507 bytes).  On the relay-fallback path the encrypted A/V stream IS
/// forwarded through the relay too (as `RelayData` — which is why the per-session rate
/// cap / encoder hint exists), but it is sent in MTU-sized datagrams that stay far below
/// this cap; the bound is therefore driven by the largest single control `DataMsg` (the
/// avatar), not by media.  Oversized datagrams are dropped (UDP — the sender's stream adapts).
pub const MAX_RELAY_PAYLOAD: usize = 64 * 1024; // 64 KB — covers JSON-expanded avatar/cursor DataMsgs
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
	// B12: ahash-backed maps below (AHashMap/AHashSet) — randomly seeded so an attacker
	// can't grief us with colliding keys, but faster than std SipHash on the hot path.
	devices: AHashMap<DeviceId, Device>,
	sessions: AHashMap<SessionId, Session>,
	/// Stable mapping pubkey → (id, last-used) so a returning device keeps the SAME
	/// 9-digit ID across reconnects/restarts (the client persists its identity).
	/// Survives the device's TTL eviction; gc() refreshes entries of registered
	/// devices and reaps mappings offline past [`PUBKEY_TTL`].
	by_pubkey: AHashMap<PublicKey, (DeviceId, Instant)>,
	/// Reverse index of every id currently held in [`Self::by_pubkey`], kept exactly in
	/// sync with its value set. Lets id minting test a candidate for collision in O(1)
	/// instead of an O(n) scan of `by_pubkey` — without it a Register flood makes each new
	/// registration cost more CPU as the map grows (a super-linear feedback loop that, on a
	/// single-task event loop, stalls all clients).
	assigned_ids: AHashSet<DeviceId>,
	/// Operator bandwidth limits (default: unlimited — see [`Limits`]).
	limits: Limits,
	/// Per-device + per-IP rate/volume meters (only populated when a limit is set).
	user_meters: AHashMap<DeviceId, Meter>,
	ip_meters: AHashMap<IpAddr, Meter>,
	/// Per-SESSION rate/volume meters (only when `per_session_*` is set). Keyed by the
	/// relay SessionId so each session is metered independently of the device's other
	/// sessions. Reaped by gc() like the other meter maps.
	session_meters: AHashMap<SessionId, Meter>,
	/// B6: reusable serialization buffer for the RelayData forward path, so the hottest
	/// path doesn't heap-allocate a fresh Vec per forwarded datagram. Only ever touched by
	/// the single-task event loop, so it needs no locking.
	scratch: Vec<u8>,
}

impl Relay {
	/// Bind the relay's UDP socket. Pass `127.0.0.1:0` in tests to get an ephemeral port.
	pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
		// A9: build the UDP socket via socket2 so we can enlarge the kernel buffers BEFORE
		// bind. The default SO_RCVBUF (~208 KB on Linux) overflows under a burst across many
		// sessions or a brief scheduling hiccup and silently drops relayed datagrams; a roomy
		// recv buffer (plus a smaller send buffer) absorbs those bursts. The kernel clamps the
		// request to net.core.rmem_max/wmem_max, so we log the size we actually got. The
		// buffer-size sets are best-effort (a platform may reject the exact value) — only
		// socket creation / nonblocking / bind failures are fatal.
		let sock2 = socket2::Socket::new(
			socket2::Domain::for_address(addr),
			socket2::Type::DGRAM,
			Some(socket2::Protocol::UDP),
		)?;
		let _ = sock2.set_recv_buffer_size(8 << 20); // request 8 MiB recv buffer
		let _ = sock2.set_send_buffer_size(4 << 20); // request 4 MiB send buffer
		sock2.set_nonblocking(true)?; // tokio's UdpSocket::from_std requires non-blocking
		sock2.bind(&addr.into())?;
		match sock2.recv_buffer_size() {
			Ok(sz) => tracing::info!(%addr, recv_buf = sz, "relay UDP socket bound"),
			Err(e) => {
				tracing::warn!(%addr, "relay UDP socket bound (recv_buffer_size query failed: {e})")
			}
		}
		let sock = UdpSocket::from_std(std::net::UdpSocket::from(sock2))?;
		Ok(Self {
			sock,
			devices: AHashMap::new(),
			sessions: AHashMap::new(),
			by_pubkey: AHashMap::new(),
			assigned_ids: AHashSet::new(),
			limits: Limits::default(),
			user_meters: AHashMap::new(),
			ip_meters: AHashMap::new(),
			session_meters: AHashMap::new(),
			scratch: Vec::new(),
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
		// A20: split the GC into two cadences. Devices/sessions expire on a tight 10s tick
		// (keeps the TTLs honest), but the O(by_pubkey) stable-ID scan + map-cap eviction +
		// meter reaping — which walk potentially-large maps — run on a slower 60s tick so that
		// O(n) sweep can't stall datagram forwarding on this single-task event loop.
		let mut gc_fast = tokio::time::interval(Duration::from_secs(10));
		let mut gc_slow = tokio::time::interval(Duration::from_secs(60));
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
						// The replies returned here are the rare ONE-SHOT control/rendezvous
						// datagrams (Registered / HeartbeatAck / Incoming / PeerFound / Error) —
						// tiny, infrequent, and NOT recoverable by stream adaptation or any
						// retransmission: the relay never resends them and connect()/register()
						// just time out (3s → TargetUnreachable / register failure). So unlike
						// the RelayData hot path — which uses non-blocking try_send_to inline in
						// handle() (see B6) precisely so a slow peer can't head-of-line block
						// recv_from, and where a WouldBlock drop is just UDP loss the stream
						// adapts to — deliver these with an awaited send_to. tokio awaits socket
						// writability, so a transient full SO_SNDBUF under heavy RelayData load
						// can't silently drop an unrelated peer's connection setup; awaiting a
						// handful of small control datagrams can't meaningfully stall the loop.
						if let Err(e) = self.sock.send_to(&bytes, to).await {
							tracing::debug!(%to, error = %e, "relay: control reply send failed");
						}
					}
				}
				_ = gc_fast.tick() => self.gc_devices_sessions(Self::now()),
				_ = gc_slow.tick() => self.gc(),
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
				// as a misleading rendezvous/handshake TIMEOUT.
				//
				// WIRE-COMPAT: we reply with `ErrCode::Protocol` (variant index 3, present
				// in ALL released builds) rather than `ErrCode::IncompatibleVersion` (variant
				// index 5, only in builds that already carry the new variant). An old client
				// that predates `IncompatibleVersion` cannot decode variant-index 5 at all —
				// bincode returns a hard error and `handle_datagram` silently drops the entire
				// datagram — so the "update required" path is unreachable and the old client
				// just sees a generic REGISTER_TIMEOUT instead. `Protocol` is decodable by
				// every existing build, so the old client at least fast-fails rather than
				// hanging. New clients (that carry `IncompatibleVersion`) decode `Protocol`
				// fine too and fail quickly via the `register_error` path.
				//
				// `IncompatibleVersion` is reserved for relay→client notifications where BOTH
				// ends are known to be new enough to decode it (a two-phase rollout: ship the
				// decoder first, only start emitting the code once it's universal).
				if version != PROTOCOL_VERSION {
					tracing::warn!(%from, version, expected = PROTOCOL_VERSION, "rejecting register: incompatible protocol version");
					return Some((
						Self::err(ErrCode::Protocol, "incompatible protocol version"),
						from,
					));
				}
				// DoS-throttle mitigation: rate-limit Register by source IP so an attacker
				// who knows a victim's public X25519 key (broadcast in every handshake + LAN
				// beacon) cannot flood Register{pubkey: victim_pubkey} to overwrite the live
				// device's addr/token and cause ID-takeover / heartbeat-flap DoS.
				// We use allow_signal (rate-only, no permanent volume lockout) so a legitimate
				// device that restarts and re-registers from a new IP is only throttled, not
				// permanently blocked. For a known pubkey the real DeviceId is looked up so the
				// per-user meter applies. For a brand-new (unknown) pubkey we use the
				// out-of-range sentinel DeviceId(0); allow_inner skips the per-user bucket for
				// sentinel values (0 < DeviceId::MIN), so only the per-IP axis is charged — the
				// meaningful bound for DoS. Without this guard every first-time registration
				// would drain the SAME DeviceId(0) user bucket, throttling all new devices
				// relay-wide when --user-rate is set without --ip-rate.
				// TODO: full proof-of-possession challenge/response is the complete fix — this
				// rate-limit only raises the cost of the attack, it does not prevent it.
				let provisional_id = self
					.by_pubkey
					.get(&pubkey)
					.map(|e| e.0)
					.unwrap_or(DeviceId(0));
				if !self.allow_signal(provisional_id, from.ip(), datagram.len().max(MAX_DATAGRAM)) {
					tracing::debug!(%from, "register rate-limited (DoS throttle)");
					return None;
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
				tracing::info!(requester = %id, %target, "relay: Connect request received");
				let Some(tdev) = self.devices.get(&target).cloned() else {
					tracing::warn!(%target, "relay: Connect target NOT online");
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
				// Rate-limit the forwarded Incoming to guard against Connect-flood abuse, but
				// intentionally skip the cumulative VOLUME cap (use allow_signal, not allow).
				// The volume cap is monotonic — once an IP/device's total exceeds the cap it
				// never recovers within the meter's lifetime — so charging rendezvous signaling
				// against it would permanently lock out new relay-fallback connections from any
				// device behind that NAT/IP once the data budget is exhausted. Rate-only limiting
				// still prevents reflection/amplification abuse. No-op when no limit is configured.
				// IMPORTANT: evaluated BEFORE sessions.insert so a cap-rejected Connect
				// does not leave a stale session record in the map (the session is never
				// inserted, so there is nothing to clean up on the early return).
				if !self.allow_signal(id, from.ip(), hello.len()) {
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
				tracing::info!(%target, target_addr = %tdev.addr, "relay: forwarding Incoming to target");
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
				// Rate-limit the forwarded PeerFound to guard against Accept-flood abuse, but
				// intentionally skip the cumulative VOLUME cap (use allow_signal, not allow) —
				// mirrors the allow_signal() call on the Connect side. See the Connect block
				// above for the full rationale: volume-capping rendezvous signaling would
				// permanently lock out new connections once the data budget is exhausted.
				// No-op when no limit is configured (the default).
				if !self.allow_signal(id, from.ip(), answer.len()) {
					return None;
				}
				let _ = requester_id; // used for symmetry with Connect; may wire to metrics later
						  // Tell the requester the target accepted, with the target's address — and
						  // advertise the per-session forwarding cap so a relayed client starts its
						  // encoder within the pipe (0 = uncapped).
				Some((
					encode(&RelayMsg::PeerFound {
						target: id,
						target_addr: from,
						session,
						answer,
						rate_cap_kbps: self.session_cap_kbps(),
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
				// a full-rate UDP reflector/amplifier toward a session peer. Even the relayed
				// A/V path sends MTU-sized datagrams (the largest legitimate one is a control
				// DataMsg — the avatar; see MAX_RELAY_PAYLOAD), so anything this large is abuse
				// or a bug.
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
				// sending device / source IP / SESSION is over its rate or volume cap.
				if !self.allow(id, from.ip(), session, payload.len()) {
					return None;
				}
				// B6: forward the hottest path WITHOUT a fresh per-datagram heap allocation.
				// `encode()` (used by the rare control replies above) allocates a new Vec on
				// every call; here we serialize the RelayData frame into the reusable scratch
				// buffer and send it inline (the "multi-send cases send inline" path noted on
				// `handle`), so a busy relay doesn't churn one allocation per forwarded datagram.
				// A6: try_send_to so a backpressured peer can't head-of-line block recv for the
				// other sessions (a full send buffer drops this datagram like any UDP loss).
				self.scratch.clear();
				bincode::serialize_into(
					&mut self.scratch,
					&RelayMsg::RelayData { session, payload },
				)
				.expect("protocol messages are always serializable");
				let _ = self.sock.try_send_to(&self.scratch, dest);
				None
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
		// (3) `by_pubkey` is capped at MAX_PUBKEY_MAPPINGS: gc() amortises offline eviction
		//     over its 10-second period (already O(n)) instead of stalling the hot path.
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
				// Bound the map: gc() proactively evicts offline mappings when the map is
				// at or above MAX_PUBKEY_MAPPINGS (amortised O(n) every 10 s, not per-packet).
				// Between gc cycles the map may briefly exceed the cap under a flood; that is
				// acceptable — memory is the concern, not an exact count. Online devices
				// keep their IDs regardless; only offline mappings are culled by gc.
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

	fn authed(&self, id: DeviceId, token: Token) -> bool {
		self.devices.get(&id).is_some_and(|d| d.token.ct_eq(&token))
	}

	/// Charge a `sz`-byte relayed datagram (from device `id` / source `ip`, on relay
	/// `session`) against the operator limits. Returns false when over the rate or volume
	/// cap; the caller then drops the datagram. No-op (always true) when no limit is set.
	fn allow(&mut self, id: DeviceId, ip: IpAddr, session: SessionId, sz: usize) -> bool {
		self.allow_inner(id, ip, sz, false, Some(session))
	}

	/// The per-session forwarding rate cap advertised to a relayed client in
	/// `PeerFound.rate_cap_kbps`, in **kbit/s** (`0` = no per-session cap configured). Only
	/// the dedicated per-session axis is signaled — the per-device/per-IP caps are shared
	/// across a device's traffic, so they don't map cleanly to one session's bitrate.
	fn session_cap_kbps(&self) -> u32 {
		match self.limits.per_session_bps {
			Some(bps) => ((bps.saturating_mul(8)) / 1000).min(u32::MAX as u64) as u32,
			None => 0,
		}
	}

	/// Charge a connection-setup signaling message (Connect/Accept) against the operator
	/// rate limit ONLY — intentionally skipping the cumulative volume cap.
	///
	/// The volume cap is a one-way monotonic counter (total never recovers). Folding
	/// rendezvous signaling into the same budget as bulk RelayData means that once an
	/// IP/device hits its data cap, no NEW relay-fallback connection can be established
	/// from behind that IP — even from an entirely different device sharing a NAT. Rate
	/// limiting still applies to prevent Connect/Accept flood abuse; only the permanent
	/// volume lockout is avoided.
	fn allow_signal(&mut self, id: DeviceId, ip: IpAddr, sz: usize) -> bool {
		// Rendezvous signaling isn't bound to an established session's data budget (the
		// session may not exist yet), so the per-session axis doesn't apply here.
		self.allow_inner(id, ip, sz, true, None)
	}

	/// Shared implementation for [`allow`] and [`allow_signal`].
	/// When `rate_only` is true, the cumulative volume (`total`) axis is skipped so
	/// connection-setup messages (Connect/Accept) are never permanently locked out by
	/// the data cap. `session` (Some only on the RelayData hot path) engages the
	/// per-session meter alongside the per-device/per-IP axes.
	fn allow_inner(
		&mut self,
		id: DeviceId,
		ip: IpAddr,
		sz: usize,
		rate_only: bool,
		session: Option<SessionId>,
	) -> bool {
		if self.limits.is_unlimited() {
			return true;
		}
		let now = Self::now();
		let sz = sz as u64;
		let (ubps, utot) = (
			self.limits.per_user_bps,
			if rate_only {
				None
			} else {
				self.limits.per_user_total
			},
		);
		let (ibps, itot) = (
			self.limits.per_ip_bps,
			if rate_only {
				None
			} else {
				self.limits.per_ip_total
			},
		);
		let (sbps, stot) = (
			self.limits.per_session_bps,
			if rate_only {
				None
			} else {
				self.limits.per_session_total
			},
		);
		// The per-session axis engages only on the RelayData hot path (a real SessionId).
		let session_active = (sbps.is_some() || stot.is_some()) && session.is_some();
		// Only engage the per-user meter for a validated DeviceId (id.0 >= DeviceId::MIN).
		// The Register path uses the out-of-range sentinel DeviceId(0) for brand-new pubkeys,
		// and allowing it into the user-meter would make ALL fresh registrations share one
		// token bucket — throttling an entire kiosk/appliance fleet's first-boot registrations
		// whenever --user-rate is configured without --ip-rate.
		let user_active = (ubps.is_some() || utot.is_some()) && id.0 >= pulsar_proto::DeviceId::MIN;
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
		if session_active {
			let s = session.unwrap();
			let m = self
				.session_meters
				.entry(s)
				.or_insert_with(|| Meter::new(now));
			m.last_active = now;
			if !m.would_allow(now, sz, sbps, stot) {
				return false;
			}
		}
		// All approved → commit. The same `now` makes each refill an identical no-op delta.
		if user_active {
			self.user_meters
				.get_mut(&id)
				.unwrap()
				.charge(now, sz, ubps, utot);
		}
		if session_active {
			self.session_meters
				.get_mut(&session.unwrap())
				.unwrap()
				.charge(now, sz, sbps, stot);
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

	/// The full periodic sweep (run on the slower 60s cadence in [`Self::run`]): expire
	/// stale devices/sessions AND do the heavier O(by_pubkey) scan + meter reaping.
	fn gc(&mut self) {
		self.gc_at(Self::now());
	}

	/// A20: the cheap half of GC, run on the tight 10s cadence — expire stale devices and
	/// sessions only. Kept separate from the O(by_pubkey) scan + meter reaping (which run on
	/// the slower 60s cadence via [`Self::gc`]) so that O(n) sweep never stalls forwarding.
	fn gc_devices_sessions(&mut self, now: Instant) {
		self.devices
			.retain(|_, d| now.duration_since(d.last_seen) < DEVICE_TTL);
		self.sessions
			.retain(|_, s| now.duration_since(s.last_seen) < SESSION_TTL);
	}

	/// [`Self::gc`] against an explicit `now`, so tests can drive long horizons. Performs the
	/// FULL sweep (cheap device/session expiry + the heavier stable-ID/meter maintenance).
	fn gc_at(&mut self, now: Instant) {
		self.gc_devices_sessions(now);
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
		// If a flood has pushed by_pubkey above MAX_PUBKEY_MAPPINGS, evict the oldest
		// OFFLINE mappings in bulk here — amortised O(n) every 10 s, not O(n) per
		// registration on the hot path. Online devices are never rotated. We collect
		// offline candidates (already O(n) to scan), sort by last-used, and drop the
		// oldest until the map is back below the cap (or no offline candidates remain).
		if self.by_pubkey.len() >= MAX_PUBKEY_MAPPINGS {
			let devices = &self.devices;
			let mut offline: Vec<(Instant, PublicKey, DeviceId)> = self
				.by_pubkey
				.iter()
				.filter(|(_, (id, _))| !devices.contains_key(id))
				.map(|(pk, (id, last))| (*last, *pk, *id))
				.collect();
			// Sort ascending by last-used (oldest first = evict first).
			offline.sort_unstable_by_key(|(last, _, _)| *last);
			for (_, pk, id) in offline {
				if self.by_pubkey.len() < MAX_PUBKEY_MAPPINGS {
					break;
				}
				self.by_pubkey.remove(&pk);
				self.assigned_ids.remove(&id);
			}
		}
		// Reap idle rate-limit meters so the maps don't grow unbounded.
		self.user_meters
			.retain(|_, m| now.saturating_duration_since(m.last_active) < METER_TTL);
		self.ip_meters
			.retain(|_, m| now.saturating_duration_since(m.last_active) < METER_TTL);
		self.session_meters
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
		assert_ne!(
			after.requester, c_id,
			"attacker must not become the requester"
		);

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
		assert!(
			connect(huge, 0x1111, &mut relay).is_none(),
			"oversized hello must be dropped"
		);
		assert!(
			!relay.sessions.contains_key(&0x1111),
			"no session for a dropped Connect"
		);
		// A realistic hello (pubkey||salt||LAN ≈ 70 B) is forwarded to the target's address.
		let (reply, to) =
			connect(vec![7u8; 70], 0x2222, &mut relay).expect("normal hello forwarded");
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
		assert!(
			relay.sessions.contains_key(&session),
			"session must exist after Connect"
		);

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
		assert!(
			reply.is_none(),
			"oversized answer must be dropped — no PeerFound emitted"
		);

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
		let (id2, _) = relay.register(
			"203.0.113.9:1001".parse().unwrap(),
			[2u8; 32],
			Some(multibyte),
		);
		let stored2 = relay.devices.get(&id2).unwrap().name.as_ref().unwrap();
		assert!(stored2.len() <= MAX_NAME_LEN);
		assert!(
			stored2.chars().all(|c| c == 'ş'),
			"must not split a codepoint"
		);
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
		assert!(
			relay.assigned_ids.is_empty(),
			"reverse index must track reaping"
		);
	}

	// When by_pubkey hits its size cap, gc() evicts the OLDEST OFFLINE mappings — never an
	// online device's — so a flood can't grow the map without bound while live devices keep
	// their stable IDs.  Registration itself no longer blocks on an O(n) scan; the eviction
	// is amortised into the periodic gc() call that already iterates the map.
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
		// One more fresh pubkey: the map briefly exceeds the cap until gc() runs (no O(n)
		// eviction on the hot path).
		let (new_id, _) = relay.register(addr, [0xBB; 32], None);
		assert_eq!(
			relay.by_pubkey.len(),
			MAX_PUBKEY_MAPPINGS + 1,
			"map grows by one before gc"
		);
		assert!(relay.assigned_ids.contains(&new_id));
		// After gc() the map is trimmed back to ≤ MAX_PUBKEY_MAPPINGS. The online device's
		// mapping must survive; only offline stale entries are culled.
		relay.gc_at(t0 + Duration::from_secs(1));
		assert!(
			relay.by_pubkey.len() <= MAX_PUBKEY_MAPPINGS,
			"gc must trim map back to cap"
		);
		assert!(
			relay.by_pubkey.values().any(|&(v, _)| v == online_id),
			"online device's mapping must survive eviction"
		);
		assert!(relay.assigned_ids.contains(&new_id));
		let _ = t0;
	}

	// Register rate-limit is no longer a no-op: flooding Register from one IP eventually
	// causes handle() to return None (dropped), while a single Register from a fresh IP
	// with an identical pubkey still succeeds.  Verifies the bug-fix for the hard-coded
	// `0` charge in allow_signal that made the throttle permanently bypass-able.
	#[tokio::test]
	async fn register_rate_limit_throttles_flood_from_single_ip() {
		// per_ip_bps = MAX_DATAGRAM (1400 B/s): the token bucket starts full at 1 second of
		// rate = 1400 tokens, so the FIRST Register (charged 1400 B) passes; every subsequent
		// one at the same instant is dropped because the bucket is empty.
		let limits = Limits {
			per_ip_bps: Some(MAX_DATAGRAM as u64),
			..Limits::default()
		};
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap())
			.await
			.unwrap()
			.with_limits(limits);

		let flooder_ip: SocketAddr = "203.0.113.1:1234".parse().unwrap();
		let victim_ip: SocketAddr = "203.0.113.2:5678".parse().unwrap();

		// Build a valid Register datagram (version + fresh pubkey).
		let make_register = |pk: PublicKey| {
			encode(&ClientMsg::Register {
				version: PROTOCOL_VERSION,
				pubkey: pk,
				name: None,
			})
		};

		// First Register from the flooder's IP — should pass (bucket full).
		let first = relay.handle(&make_register([0xAA; 32]), flooder_ip);
		assert!(first.is_some(), "first Register must pass (bucket full)");

		// Subsequent Registers from the SAME IP at the same instant — must be dropped.
		let mut any_dropped = false;
		for i in 0..10u8 {
			let mut pk = [0u8; 32];
			pk[0] = i.wrapping_add(1);
			if relay.handle(&make_register(pk), flooder_ip).is_none() {
				any_dropped = true;
				break;
			}
		}
		assert!(
			any_dropped,
			"flood from one IP must be rate-limited (handle returns None)"
		);

		// A single Register from a DIFFERENT IP must still succeed — the per-IP meter is
		// independent; the flood from another address must not lock out this one.
		let legit = relay.handle(&make_register([0xFF; 32]), victim_ip);
		assert!(
			legit.is_some(),
			"Register from a fresh IP must not be blocked by another IP's flood"
		);
	}

	// When ONLY per_user_bps is set (no per_ip_bps), two brand-new pubkeys from DIFFERENT
	// IPs must both succeed at the same instant. Before the fix, both hits the SAME
	// DeviceId(0) shared user bucket, so the second registration was incorrectly throttled.
	#[tokio::test]
	async fn register_fresh_pubkeys_from_different_ips_not_throttled_by_user_meter() {
		// per_user_bps = MAX_DATAGRAM (1400 B/s): the token bucket starts full at exactly
		// one Register's worth of tokens. If the sentinel DeviceId(0) were shared across
		// all fresh registrations the FIRST one would drain the bucket and the SECOND would
		// be dropped — even from a completely different IP. The fix skips the user meter for
		// the out-of-range sentinel so both must succeed.
		let limits = Limits {
			per_user_bps: Some(MAX_DATAGRAM as u64),
			..Limits::default()
		};
		let mut relay = Relay::bind("127.0.0.1:0".parse().unwrap())
			.await
			.unwrap()
			.with_limits(limits);

		let ip_a: SocketAddr = "203.0.113.10:1000".parse().unwrap();
		let ip_b: SocketAddr = "203.0.113.11:2000".parse().unwrap();

		let make_register = |pk: PublicKey| {
			encode(&ClientMsg::Register {
				version: PROTOCOL_VERSION,
				pubkey: pk,
				name: None,
			})
		};

		// Two brand-new (unknown) pubkeys each from a distinct IP — both must be accepted.
		let r1 = relay.handle(&make_register([0xA1; 32]), ip_a);
		let r2 = relay.handle(&make_register([0xB2; 32]), ip_b);
		assert!(
			r1.is_some(),
			"first fresh-pubkey Register must succeed under user-only rate limit"
		);
		assert!(r2.is_some(), "second fresh-pubkey Register from different IP must also succeed (sentinel must not share user bucket)");
	}
}
