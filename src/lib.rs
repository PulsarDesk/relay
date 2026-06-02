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
use std::net::SocketAddr;

use pulsar_proto::{
	decode, encode, ClientMsg, DeviceId, ErrCode, PublicKey, RelayMsg, SessionId, Token,
};
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};

/// How long a device may go without a heartbeat before it's reaped.
pub const DEVICE_TTL: Duration = Duration::from_secs(30);
/// How long a rendezvous session lingers without traffic.
pub const SESSION_TTL: Duration = Duration::from_secs(120);

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
}

impl Relay {
	/// Bind the relay's UDP socket. Pass `127.0.0.1:0` in tests to get an ephemeral port.
	pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
		let sock = UdpSocket::bind(addr).await?;
		Ok(Self {
			sock,
			devices: HashMap::new(),
			sessions: HashMap::new(),
		})
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
					let (n, from) = res?;
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
				let Some(sess) = self.sessions.get_mut(&session) else {
					return Some((Self::err(ErrCode::Protocol, "no such session"), from));
				};
				sess.last_seen = Self::now();
				// Forward to the *other* end of the session.
				let dest = if id == sess.requester {
					sess.target_addr
				} else if id == sess.target {
					sess.requester_addr
				} else {
					return Some((Self::err(ErrCode::Protocol, "not a session member"), from));
				};
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
		let mut rng = rand::thread_rng();
		let id = loop {
			let candidate = DeviceId::random(&mut rng);
			if !self.devices.contains_key(&candidate) {
				break candidate;
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

	fn err(code: ErrCode, message: &str) -> Vec<u8> {
		encode(&RelayMsg::Error {
			code,
			message: message.to_string(),
		})
	}

	/// Drop stale devices and sessions.
	fn gc(&mut self) {
		let now = Self::now();
		self.devices
			.retain(|_, d| now.duration_since(d.last_seen) < DEVICE_TTL);
		self.sessions
			.retain(|_, s| now.duration_since(s.last_seen) < SESSION_TTL);
	}
}
