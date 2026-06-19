//! Integration test: drive the relay with raw UDP sockets the way two real
//! clients would — register, rendezvous, accept, and relay-forward payloads.

use std::net::SocketAddr;
use std::time::Duration;

use pulsar_proto::{
	decode, encode, ClientMsg, DeviceId, ErrCode, RelayMsg, Token, PROTOCOL_VERSION,
};
use pulsar_relay::Relay;
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn start_relay() -> SocketAddr {
	let relay = Relay::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
	let addr = relay.local_addr().unwrap();
	tokio::spawn(relay.run());
	addr
}

async fn client() -> UdpSocket {
	UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn send(sock: &UdpSocket, relay: SocketAddr, msg: &ClientMsg) {
	sock.send_to(&encode(msg), relay).await.unwrap();
}

async fn recv(sock: &UdpSocket) -> RelayMsg {
	let mut buf = vec![0u8; 65_536];
	let (n, _) = timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
		.await
		.expect("timed out waiting for relay reply")
		.unwrap();
	decode(&buf[..n]).expect("decodable RelayMsg")
}

async fn register(sock: &UdpSocket, relay: SocketAddr, name: &str) -> (DeviceId, Token) {
	// Derive a distinct pubkey per device name — real devices have distinct
	// identities, and the relay now maps pubkey → id (stable id), so two different
	// devices must present different pubkeys (and the same name → same identity).
	let mut pubkey = [0u8; 32];
	for (i, b) in name.bytes().take(32).enumerate() {
		pubkey[i] = b;
	}
	send(
		sock,
		relay,
		&ClientMsg::Register {
			version: PROTOCOL_VERSION,
			pubkey,
			name: Some(name.into()),
		},
	)
	.await;
	match recv(sock).await {
		RelayMsg::Registered { id, token } => (id, token),
		other => panic!("expected Registered, got {other:?}"),
	}
}

#[tokio::test]
async fn registration_assigns_unique_nine_digit_ids() {
	let relay = start_relay().await;
	let a = client().await;
	let b = client().await;
	let (id_a, _) = register(&a, relay, "A").await;
	let (id_b, _) = register(&b, relay, "B").await;
	assert_ne!(id_a, id_b, "two devices got the same id");
	assert_eq!(id_a.0.to_string().len(), 9);
	assert_eq!(id_b.0.to_string().len(), 9);
}

#[tokio::test]
async fn same_identity_keeps_its_id_across_reregistration() {
	// A device that persists its identity (same pubkey) must get the SAME 9-digit id
	// when it re-registers — this is what makes the user's device ID stable.
	let relay = start_relay().await;
	let first = client().await;
	let (id1, _) = register(&first, relay, "Stable").await;
	let again = client().await;
	let (id2, _) = register(&again, relay, "Stable").await; // same name → same pubkey
	assert_eq!(
		id1, id2,
		"same identity must keep its id across re-registration"
	);
}

#[tokio::test]
async fn heartbeat_requires_valid_token() {
	let relay = start_relay().await;
	let a = client().await;
	let (id, token) = register(&a, relay, "A").await;

	send(&a, relay, &ClientMsg::Heartbeat { id, token }).await;
	assert!(matches!(recv(&a).await, RelayMsg::HeartbeatAck));

	send(
		&a,
		relay,
		&ClientMsg::Heartbeat {
			id,
			token: Token([0xFF; 16]),
		},
	)
	.await;
	assert!(matches!(
		recv(&a).await,
		RelayMsg::Error {
			code: ErrCode::NotRegistered,
			..
		}
	));
}

#[tokio::test]
async fn connect_to_offline_target_errors() {
	let relay = start_relay().await;
	let a = client().await;
	let (id_a, token_a) = register(&a, relay, "A").await;

	send(
		&a,
		relay,
		&ClientMsg::Connect {
			id: id_a,
			token: token_a,
			target: DeviceId::new(123_456_789).unwrap(),
			session: 1,
			hello: vec![],
		},
	)
	.await;
	assert!(matches!(
		recv(&a).await,
		RelayMsg::Error {
			code: ErrCode::TargetOffline,
			..
		}
	));
}

#[tokio::test]
async fn full_rendezvous_and_relay_forwarding() {
	let relay = start_relay().await;
	let a = client().await;
	let b = client().await;
	let (id_a, token_a) = register(&a, relay, "A").await;
	let (id_b, token_b) = register(&b, relay, "B").await;
	let a_addr = a.local_addr().unwrap();
	let b_addr = b.local_addr().unwrap();
	let session = 0xABCD;

	// A asks the relay to reach B.
	send(
		&a,
		relay,
		&ClientMsg::Connect {
			id: id_a,
			token: token_a,
			target: id_b,
			session,
			hello: vec![1, 2, 3],
		},
	)
	.await;

	// B receives the incoming request, with A's observed address.
	match recv(&b).await {
		RelayMsg::Incoming {
			from,
			from_addr,
			session: s,
			hello,
		} => {
			assert_eq!(from, id_a);
			assert_eq!(from_addr, a_addr);
			assert_eq!(s, session);
			assert_eq!(hello, vec![1, 2, 3]);
		}
		other => panic!("B expected Incoming, got {other:?}"),
	}

	// B accepts.
	send(
		&b,
		relay,
		&ClientMsg::Accept {
			id: id_b,
			token: token_b,
			session,
			answer: vec![4, 5, 6],
		},
	)
	.await;

	// A learns B's address + answer.
	match recv(&a).await {
		RelayMsg::PeerFound {
			target,
			target_addr,
			session: s,
			answer,
			..
		} => {
			assert_eq!(target, id_b);
			assert_eq!(target_addr, b_addr);
			assert_eq!(s, session);
			assert_eq!(answer, vec![4, 5, 6]);
		}
		other => panic!("A expected PeerFound, got {other:?}"),
	}

	// Relay-fallback path: A -> relay -> B.
	send(
		&a,
		relay,
		&ClientMsg::RelayData {
			id: id_a,
			token: token_a,
			session,
			payload: vec![9, 9, 9],
		},
	)
	.await;
	match recv(&b).await {
		RelayMsg::RelayData {
			session: s,
			payload,
		} => {
			assert_eq!(s, session);
			assert_eq!(payload, vec![9, 9, 9]);
		}
		other => panic!("B expected RelayData, got {other:?}"),
	}

	// ...and back B -> relay -> A.
	send(
		&b,
		relay,
		&ClientMsg::RelayData {
			id: id_b,
			token: token_b,
			session,
			payload: vec![7, 7],
		},
	)
	.await;
	match recv(&a).await {
		RelayMsg::RelayData { payload, .. } => assert_eq!(payload, vec![7, 7]),
		other => panic!("A expected RelayData, got {other:?}"),
	}
}
